import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const publicDir=path.join(__dirname,'public');
const dataDir=process.env.DATA_DIR||'/data';
fs.mkdirSync(dataDir,{recursive:true});
const dbPath=path.join(dataDir,'varamin.sqlite');
const db=new DatabaseSync(dbPath);
db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY,time TEXT NOT NULL,name TEXT,phone TEXT,category TEXT,place TEXT,text TEXT NOT NULL,anonymous INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS donations(id TEXT PRIMARY KEY,time TEXT NOT NULL,name TEXT,amount TEXT NOT NULL,phone TEXT,note TEXT,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS visits(visitor_id TEXT PRIMARY KEY,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,views INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS visit_days(day TEXT PRIMARY KEY,unique_visitors INTEGER NOT NULL DEFAULT 0,page_views INTEGER NOT NULL DEFAULT 0);`);

const ADMIN_API_KEY=process.env.ADMIN_API_KEY||'';
if(!ADMIN_API_KEY) console.warn('ADMIN_API_KEY is not set; admin API access is disabled until it is configured.');
const attempts=new Map();
function json(res,status,data,headers={}){const body=JSON.stringify(data);res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'strict-origin-when-cross-origin','Permissions-Policy':'camera=(),microphone=(),geolocation=()',...headers});res.end(body)}
function cleanString(v,max=20000){return String(v??'').trim().slice(0,max)}
async function body(req){let s='';for await(const chunk of req)s+=chunk;if(s.length>1024*1024)throw Error('payload too large');return JSON.parse(s||'{}')}
function safePath(urlPath){const p=decodeURIComponent(urlPath.split('?')[0]);const rel=p==='/'?'index.html':p.replace(/^\/+/, '');const full=path.resolve(publicDir,rel);return full.startsWith(path.resolve(publicDir)+path.sep)?full:null}
function sendFile(res,file){const ext=path.extname(file).toLowerCase();const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.txt':'text/plain; charset=utf-8','.json':'application/json; charset=utf-8','.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png','.svg':'image/svg+xml','.webp':'image/webp'};res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream','Cache-Control':ext==='.html'?'no-cache':'public, max-age=86400'});fs.createReadStream(file).pipe(res)}
function internalAdmin(req){const got=Buffer.from(cleanString(req.headers['x-admin-key'],500));const want=Buffer.from(ADMIN_API_KEY);return !!ADMIN_API_KEY && got.length===want.length && crypto.timingSafeEqual(got,want)}
function visitorHash(req){const ua=cleanString(req.headers['user-agent'],300);const ip=req.headers['x-forwarded-for']?.split(',')[0]?.trim()||req.socket.remoteAddress||'unknown';return crypto.createHash('sha256').update(ip+'|'+ua+'|varamin-visitor-v1').digest('hex')}
function touchVisit(req){const now=new Date().toISOString(),day=now.slice(0,10),id=visitorHash(req);const existing=db.prepare('SELECT visitor_id FROM visits WHERE visitor_id=?').get(id);if(existing){db.prepare('UPDATE visits SET last_seen=?,views=views+1 WHERE visitor_id=?').run(now,id);db.prepare('UPDATE visit_days SET page_views=page_views+1 WHERE day=?').run(day)}else{db.prepare('INSERT INTO visits(visitor_id,first_seen,last_seen,views) VALUES(?,?,?,1)').run(id,now,now);db.prepare('INSERT INTO visit_days(day,unique_visitors,page_views) VALUES(?,?,1) ON CONFLICT(day) DO UPDATE SET unique_visitors=unique_visitors+1,page_views=page_views+1').run(day,1)}return {id}}
function stats(){const today=new Date().toISOString().slice(0,10);const t=db.prepare('SELECT unique_visitors,page_views FROM visit_days WHERE day=?').get(today)||{unique_visitors:0,page_views:0};const total=db.prepare('SELECT COUNT(*) AS c FROM visits').get().c;const active=db.prepare("SELECT COUNT(*) AS c FROM visits WHERE last_seen >= ?").get(new Date(Date.now()-5*60*1000).toISOString()).c;const reports=db.prepare('SELECT COUNT(*) AS c FROM reports').get().c;const donations=db.prepare('SELECT COUNT(*) AS c FROM donations').get().c;const reportBytes=db.prepare('SELECT COALESCE(SUM(LENGTH(text)+LENGTH(name)+LENGTH(phone)+LENGTH(place)),0) AS n FROM reports').get().n;const donationBytes=db.prepare('SELECT COALESCE(SUM(LENGTH(note)+LENGTH(name)+LENGTH(phone)+LENGTH(amount)),0) AS n FROM donations').get().n;return {todayVisitors:t.unique_visitors,todayViews:t.page_views,totalVisitors:total,activeVisitors:active,reports,donations,storageKB:Math.max(1,Math.round((reportBytes+donationBytes)/1024)),serverTime:new Date().toISOString()}}

const server=http.createServer(async(req,res)=>{try{
 const isHttps=req.headers['x-forwarded-proto']==='https'||req.socket.encrypted;
 res.setHeader('Content-Security-Policy',"default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'");
 res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains' );
 const u=new URL(req.url,`http://${req.headers.host||'localhost'}`);
 if(req.method==='GET'&&u.pathname==='/health')return json(res,200,{ok:true,service:'site',port:Number(process.env.PORT||8080),db:dbPath});
 if(req.method==='GET'&&u.pathname==='/api/config')return json(res,200,{adminUrl:process.env.ADMIN_URL||''});
 if(req.method==='POST'&&u.pathname==='/api/visit'){touchVisit(req);res.writeHead(204,{'Cache-Control':'no-store'});return res.end()}
 if(req.method==='POST'&&u.pathname==='/api/reports'){
  const b=await body(req),o={id:cleanString(b.id,100)||crypto.randomUUID(),time:cleanString(b.time,100)||new Date().toLocaleString('fa-IR'),name:cleanString(b.name,120),phone:cleanString(b.phone,80),category:cleanString(b.category,80),place:cleanString(b.place,120),text:cleanString(b.text,20000),anonymous:b.anonymous?1:0,created_at:new Date().toISOString()};
  if(o.text.length<8)return json(res,400,{error:'شرح گزارش کوتاه است.'});
  try{db.prepare('INSERT INTO reports VALUES(?,?,?,?,?,?,?,?,?)').run(o.id,o.time,o.name,o.phone,o.category,o.place,o.text,o.anonymous,o.created_at)}catch(e){if(String(e).includes('UNIQUE'))return json(res,409,{error:'این گزارش قبلاً ثبت شده است.'});throw e}
  return json(res,201,{ok:true,id:o.id})
 }
 if(req.method==='POST'&&u.pathname==='/api/donations'){
  const b=await body(req),o={id:cleanString(b.id,100)||crypto.randomUUID(),time:cleanString(b.time,100)||new Date().toLocaleString('fa-IR'),name:cleanString(b.name,120),amount:cleanString(b.amount,80),phone:cleanString(b.phone,80),note:cleanString(b.note,20000),created_at:new Date().toISOString()};
  if(!o.amount)return json(res,400,{error:'مبلغ نذر وارد نشده است.'});db.prepare('INSERT INTO donations VALUES(?,?,?,?,?,?,?)').run(o.id,o.time,o.name,o.amount,o.phone,o.note,o.created_at);return json(res,201,{ok:true,id:o.id})
 }
 if(req.method==='GET'&&u.pathname==='/api/admin/stats'){if(!internalAdmin(req))return json(res,401,{error:'دسترسی غیرمجاز'});return json(res,200,stats())}
 if(req.method==='GET'&&u.pathname==='/api/admin/reports'){if(!internalAdmin(req))return json(res,401,{error:'دسترسی غیرمجاز'});return json(res,200,{items:db.prepare('SELECT * FROM reports ORDER BY created_at DESC').all()})}
 if(req.method==='GET'&&u.pathname==='/api/admin/donations'){if(!internalAdmin(req))return json(res,401,{error:'دسترسی غیرمجاز'});return json(res,200,{items:db.prepare('SELECT * FROM donations ORDER BY created_at DESC').all()})}
 if(req.method==='GET'){
  const file=safePath(u.pathname);if(!file)return json(res,403,{error:'Forbidden'});if(fs.existsSync(file)&&fs.statSync(file).isFile())return sendFile(res,file);return sendFile(res,path.join(publicDir,'index.html'));
 }
 return json(res,404,{error:'Not found'});
}catch(e){console.error(e);return json(res,500,{error:'خطای داخلی سرور'})}});
const port=Number(process.env.PORT||8080);server.listen(port,'0.0.0.0',()=>console.log(`Varamin SITE listening on ${port}; database: ${dbPath}`));
process.on('SIGTERM',()=>{try{db.close()}finally{process.exit(0)}});
