import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const publicDir=path.join(__dirname,'admin');
const SITE_API_URL=(process.env.SITE_API_URL||'').replace(/\/$/,'');
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||'admin';
const ADMIN_API_KEY=process.env.ADMIN_API_KEY||'';
const sessions=new Map();
const attempts=new Map();
function json(res,status,data,headers={}){const body=JSON.stringify(data);res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'strict-origin-when-cross-origin','Permissions-Policy':'camera=(),microphone=(),geolocation=()',...headers});res.end(body)}
function clean(v,max=500){return String(v??'').trim().slice(0,max)}
async function body(req){let s='';for await(const c of req)s+=c;if(s.length>256*1024)throw Error('payload too large');return JSON.parse(s||'{}')}
function cookies(req){const out={};for(const p of (req.headers.cookie||'').split(';')){const i=p.indexOf('=');if(i>0)out[p.slice(0,i).trim()]=decodeURIComponent(p.slice(i+1).trim())}return out}
function admin(req){const t=cookies(req).admin_session;const exp=t&&sessions.get(t);if(!exp)return false;if(exp<Date.now()){sessions.delete(t);return false}return true}
function loginAttempts(req){const ip=req.socket.remoteAddress||'unknown',now=Date.now(),a=attempts.get(ip)||{n:0,t:now};if(now-a.t>60000){a.n=0;a.t=now}return [ip,a]}
function filePath(p){const rel=p==='/'?'index.html':p.replace(/^\/+/, '');const full=path.resolve(publicDir,decodeURIComponent(rel));return full.startsWith(path.resolve(publicDir)+path.sep)?full:null}
function sendFile(res,file){const ext=path.extname(file).toLowerCase();const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml'};res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream','Cache-Control':ext==='.html'?'no-cache':'public, max-age=86400'});fs.createReadStream(file).pipe(res)}
async function siteFetch(route,opts={}){if(!SITE_API_URL)throw Error('SITE_API_URL تنظیم نشده است');const r=await fetch(SITE_API_URL+route,{...opts,headers:{'Content-Type':'application/json','X-Admin-Key':ADMIN_API_KEY,...(opts.headers||{})}});const text=await r.text();let data={};try{data=JSON.parse(text)}catch{}if(!r.ok)throw Error(data?.error||`ارتباط با سایت اصلی ناموفق بود (${r.status})`);return data}
const server=http.createServer(async(req,res)=>{try{
 const u=new URL(req.url,`http://${req.headers.host||'localhost'}`);
 if(req.method==='GET'&&u.pathname==='/health')return json(res,200,{ok:true,service:'admin',port:Number(process.env.PORT||8000),siteApi:SITE_API_URL||null});
 if(req.method==='POST'&&u.pathname==='/api/login'){
  const [ip,a]=loginAttempts(req);if(a.n>=8)return json(res,429,{error:'تعداد تلاش‌ها زیاد است. یک دقیقه بعد دوباره امتحان کنید.'});const b=await body(req);a.n++;attempts.set(ip,a);if(clean(b.password,200)!==ADMIN_PASSWORD)return json(res,401,{error:'رمز مدیریت صحیح نیست.'});a.n=0;const token=crypto.randomBytes(32).toString('hex');sessions.set(token,Date.now()+8*60*60*1000);const secure=req.headers['x-forwarded-proto']==='https'||req.socket.encrypted;return json(res,200,{ok:true},{'Set-Cookie':`admin_session=${token}; HttpOnly; SameSite=Strict; Path=/; Path=/; Max-Age=28800${secure?'; Secure':''}`.replace('; Path=/; Path=/','; Path=/')})
 }
 if(req.method==='POST'&&u.pathname==='/api/logout'){const t=cookies(req).admin_session;if(t)sessions.delete(t);return json(res,200,{ok:true},{'Set-Cookie':'admin_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'})}
 if(u.pathname.startsWith('/api/admin/')){if(!admin(req))return json(res,401,{error:'نیاز به ورود مدیر دارد.'});const data=await siteFetch(u.pathname,{method:req.method,body:['POST','PUT','PATCH','DELETE'].includes(req.method)?JSON.stringify(await body(req)):undefined});return json(res,200,data)}
 if(req.method==='GET'){const file=filePath(u.pathname);if(!file)return json(res,403,{error:'Forbidden'});if(fs.existsSync(file)&&fs.statSync(file).isFile())return sendFile(res,file);return sendFile(res,path.join(publicDir,'index.html'))}
 return json(res,404,{error:'Not found'});
}catch(e){console.error(e);return json(res,500,{error:e.message||'خطای داخلی پنل'})}});
const port=Number(process.env.PORT||8000);server.listen(port,'0.0.0.0',()=>console.log(`Varamin ADMIN listening on ${port}; site: ${SITE_API_URL||'NOT SET'}`));
process.on('SIGTERM',()=>{sessions.clear();process.exit(0)});
