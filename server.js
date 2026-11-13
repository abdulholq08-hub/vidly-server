"use strict";
/* Vidly server — Node.js >= 20. Hech qanday npm paket kerak emas.
   Tizimda ffmpeg va ffprobe oʻrnatilgan boʻlishi shart (video sifatlari va poster uchun). */
const http=require("http"),fs=require("fs"),path=require("path"),crypto=require("crypto"),{spawn}=require("child_process");
const E=process.env;
const PORT=+E.PORT||3000;
const ROOT=__dirname,DATA=path.resolve(E.DATA_DIR||path.join(ROOT,"data")),MEDIA=path.join(DATA,"media"),PUB=path.join(ROOT,"public");
const PROD=E.NODE_ENV==="production";
if(PROD&&(!E.JWT_SECRET||E.JWT_SECRET.length<24)){console.error("JWT_SECRET (kamida 24 belgi) kerak");process.exit(1)}
const SEC=E.JWT_SECRET||"dev-secret-faqat-sinov-uchun";
const MAXB=(+E.MAX_UPLOAD_MB||2048)*1048576;
const ORIGIN=E.ALLOWED_ORIGIN||"";
const RATE=+E.USD_RATE||12500,DAY=864e5,HOLD=3*DAY;
const CATS=["Musiqa","Oʻyin","Taʼlim","Sayohat","Kulgi"];
const PLANS={w:{l:"1 hafta",usd:5,ms:7*DAY},m:{l:"1 oy",usd:30,ms:30*DAY},q:{l:"3 oy",usd:90,ms:90*DAY},y:{l:"1 yil",usd:300,ms:365*DAY}};
const ADS={d1:{l:"1 kun",usd:3,ms:DAY},d3:{l:"3 kun",usd:8,ms:3*DAY},d7:{l:"7 kun",usd:15,ms:7*DAY}};
for(const d of["v","i","p"])fs.mkdirSync(path.join(MEDIA,d),{recursive:true});

/* ---------- Maʼlumotlar bazasi (JSON fayl; keyin Postgres’ga oʻtkazish mumkin) ---------- */
const DBF=path.join(DATA,"db.json");
let DB={users:{},subs:{},views:{},secs:{},bonus:{},mon:{},wd:[],admins:[],pay:[],cfg:{card:"",holder:""},ads:{},live:{},videos:{},likes:{},cm:{},sms:{}};
try{Object.assign(DB,JSON.parse(fs.readFileSync(DBF,"utf8")))}catch(e){}
let dirty=false;const touch=()=>{dirty=true};
function flush(){if(!dirty)return;dirty=false;const t=DBF+".tmp";fs.writeFileSync(t,JSON.stringify(DB));fs.renameSync(t,DBF)}
const flushTimer=setInterval(flush,1500);
for(const s of["SIGINT","SIGTERM"])process.on(s,()=>{clearInterval(flushTimer);flush();process.exit(0)});

/* ---------- Yordamchilar ---------- */
const fail=(code,status=400)=>{const e=new Error(code);e.status=status;throw e};
const rid=()=>"a"+crypto.randomBytes(5).toString("hex");
const b64=b=>Buffer.from(b).toString("base64url");
const hmac=s=>crypto.createHmac("sha256",SEC).update(s).digest("base64url");
const sign=p=>{const h=b64(JSON.stringify({alg:"HS256",typ:"JWT"})),pl=b64(JSON.stringify(p));return h+"."+pl+"."+hmac(h+"."+pl)};
const verify=t=>{try{const[a,b,c]=String(t).split(".");const s=hmac(a+"."+b);if(s.length!==c.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(c)))return null;const p=JSON.parse(Buffer.from(b,"base64url"));return p.exp>Date.now()/1e3?p:null}catch(e){return null}};
const OPS_UZ=["20","33","50","55","77","88","90","91","93","94","95","97","98","99"];
const okPhone=p=>/^\d{9}$/.test(p)&&OPS_UZ.includes(p.slice(0,2));
const hits=new Map();
function rl(key,n,ms){const now=Date.now(),a=(hits.get(key)||[]).filter(t=>now-t<ms);if(a.length>=n){hits.set(key,a);return false}a.push(now);hits.set(key,a);return true}
setInterval(()=>{const now=Date.now();for(const[k,a]of hits){if(!a.some(t=>now-t<36e5))hits.delete(k)}},6e5).unref();
const ipOf=req=>E.TRUST_PROXY==="1"?(String(req.headers["x-forwarded-for"]||"").split(",")[0].trim()||req.socket.remoteAddress):req.socket.remoteAddress;
const auth=req=>{const h=req.headers.authorization||"",p=h.startsWith("Bearer ")?verify(h.slice(7)):null;return p&&DB.users[p.uid]?p.uid:""};
const vkey=(req,uid)=>uid||("g:"+(String(req.headers["x-viewer"]||"").replace(/[^a-z0-9]/gi,"").slice(0,24)||crypto.createHash("sha1").update(ipOf(req)||"x").digest("hex").slice(0,12)));
const isAdmin=uid=>{const u=DB.users[uid];return !!(u&&(u.user==="vidly"||DB.admins.includes(uid)))};
const sigPay=id=>hmac("pay:"+id).slice(0,24);
const json=(res,st,o)=>{res.writeHead(st,{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"});res.end(JSON.stringify(o))};
const readBody=(req,max)=>new Promise((ok,bad)=>{const c=[];let n=0;req.on("data",d=>{n+=d.length;if(n>max){req.destroy();bad(Object.assign(new Error("too_large"),{status:413}))}else c.push(d)});req.on("end",()=>ok(Buffer.concat(c)));req.on("error",bad)});
const readJson=async(req,max=3e6)=>{const b=await readBody(req,max);try{return b.length?JSON.parse(b.toString("utf8")):{}}catch(e){fail("bad_json")}};

/* ---------- SMS (Eskiz.uz) ---------- */
let eskiz={tok:"",exp:0};
async function eskizToken(){
  if(eskiz.tok&&Date.now()<eskiz.exp)return eskiz.tok;
  const fd=new FormData();fd.append("email",E.ESKIZ_EMAIL);fd.append("password",E.ESKIZ_PASSWORD);
  const r=await fetch("https://notify.eskiz.uz/api/auth/login",{method:"POST",body:fd}),j=await r.json();
  if(!j.data||!j.data.token)throw new Error("eskiz_login");
  eskiz={tok:j.data.token,exp:Date.now()+20*DAY};return eskiz.tok;
}
async function sendSms(phone,code){
  const text=(E.SMS_TEXT||"Vidly tasdiqlash kodi: {code}").replace("{code}",code);
  if(E.ESKIZ_EMAIL&&E.ESKIZ_PASSWORD){
    const tok=await eskizToken(),fd=new FormData();
    fd.append("mobile_phone","998"+phone);fd.append("message",text);fd.append("from",E.ESKIZ_FROM||"4546");
    const r=await fetch("https://notify.eskiz.uz/api/message/sms/send",{method:"POST",headers:{Authorization:"Bearer "+tok},body:fd});
    if(!r.ok){eskiz.tok="";throw new Error("sms_"+r.status)}
    return;
  }
  if(E.DEV_SMS==="1"&&!PROD){console.log("[DEV SMS] +998"+phone+" kod: "+code);return}
  const e=new Error("no_provider");e.status=503;throw e;
}
const hashCode=(phone,code)=>crypto.createHash("sha256").update(phone+":"+code+":"+SEC).digest("hex");

/* ---------- Monetizatsiya hisob-kitobi ---------- */
const MG=u=>DB.mon[u]=DB.mon[u]||{segs:[],pending:null,rej:""};
const segsOf=u=>(DB.mon[u]||{}).segs||[];
const monActive=u=>segsOf(u).some(s=>!s.u||s.u>Date.now());
const closeSegs=u=>{MG(u).segs.forEach(s=>{if(!s.u||s.u>Date.now())s.u=Date.now()})};
function grant(u,ms){closeSegs(u);MG(u).segs.push({f:Date.now(),u:ms?Date.now()+ms:0});MG(u).pending=null;MG(u).rej=""}
function extend(u,ms){const mg=MG(u),now=Date.now(),open=mg.segs.find(s=>!s.u||s.u>now);if(open){if(!open.u)return;open.u+=ms}else mg.segs.push({f:now,u:now+ms});mg.pending=null}
function extendAd(vid,ms){const a=DB.ads[vid],base=a&&a.until>Date.now()?a.until:Date.now();DB.ads[vid]={until:base+ms}}
const subsOf=id=>Object.keys(DB.subs[id]||{}).length+(DB.bonus[id]||0);
const ownVids=u=>Object.values(DB.videos).filter(v=>v.owner===u);
function stats(u){
  const vs=ownVids(u),now=Date.now(),sg=segsOf(u);let views=0,hrs=0,conf=0,pend=0;
  for(const v of vs){const vw=Object.values(DB.views[v.id]||{});views+=vw.length;if(v.kind==="long")hrs+=(DB.secs[v.id]||0)/3600;
    for(const ts of vw){if(sg.some(s=>ts>=s.f&&(!s.u||ts<=s.u))){ts<=now-HOLD?conf++:pend++}}}
  return{subs:subsOf(u),views,hrs,conf,pend,usd:Math.floor(conf/1000)*10,pusd:pend/100,vids:vs.length};
}
const paidOf=u=>DB.wd.filter(w=>w.uid===u&&w.st!=="Rad etilgan").reduce((a,w)=>a+w.amt,0);
const expirePay=()=>{const now=Date.now();for(const p of DB.pay)if(p.st==="kutilmoqda"&&p.dl<=now){p.st="muddat";touch()}};

/* ---------- Rasmlar ---------- */
function saveImg(dataUrl,dir,name,max){
  const m=/^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(String(dataUrl));
  if(!m)fail("bad_image");
  const buf=Buffer.from(m[2],"base64");if(buf.length>max)fail("image_too_large",413);
  const ext=m[1]==="jpeg"?".jpg":"."+m[1],file=name+ext;
  fs.writeFileSync(path.join(MEDIA,dir,file),buf);return`/media/${dir}/${file}`;
}
const rmMedia=url=>{try{if(url&&url.startsWith("/media/i/"))fs.unlinkSync(path.join(MEDIA,url.slice(7)))}catch(e){}};
function imgField(val,old,pref,max){
  if(val===""||val==null){rmMedia(old);return""}
  if(String(val).startsWith("data:")){const u=saveImg(val,"i",pref+crypto.randomBytes(5).toString("hex"),max);rmMedia(old);return u}
  return old||"";
}

/* ---------- Holat (klientga beriladigan koʻrinish) ---------- */
function view(uid,key){
  expirePay();
  const adm=isAdmin(uid),me=DB.users[uid],G={users:{},subs:{},views:{},secs:{},bonus:{},mon:{},wd:[],admins:DB.admins.slice(),pay:[],cfg:{},ads:DB.ads,live:{},videos:[],vc:{},lc:{},mylk:{},cm:{},stats:{},subc:{},key};
  for(const u of Object.values(DB.users)){
    if(!u.ch&&u.uid!==uid)continue;
    const full=u.uid===uid||adm;
    G.users[u.uid]={uid:u.uid,ch:u.ch,user:u.user,avatar:u.avatar,banner:u.banner,ts:u.ts,phoneOk:true,phone:full?u.phone:""};
  }
  const chs=new Set([...Object.keys(DB.subs),...Object.keys(DB.bonus),...Object.keys(G.users)]);
  for(const c of chs){const m=DB.subs[c]||{},n=Object.keys(m).length,mine=!!m[key];G.subs[c]=mine?{[key]:m[key]}:{};G.bonus[c]=n-(mine?1:0)+(DB.bonus[c]||0)}
  for(const c of Object.keys(DB.subs))for(const k of Object.keys(DB.subs[c]))G.subc[k]=(G.subc[k]||0)+1;
  for(const id of Object.keys(DB.views))G.vc[id]=Object.keys(DB.views[id]).length;
  for(const id of Object.keys(DB.likes)){G.lc[id]=Object.keys(DB.likes[id]).length;if(uid&&DB.likes[id][uid])G.mylk[id]=true}
  for(const id of Object.keys(DB.cm))G.cm[id]=DB.cm[id].map(c=>({n:c.n,t:c.t}));
  for(const v of Object.values(DB.videos)){
    G.videos.push({id:v.id,t:v.t,c:v.c,kind:v.kind,owner:v.owner,dur:v.dur,ts:v.ts,adult:v.adult,ww:v.ww,hh:v.hh,status:v.status,orig:`/media/v/${v.id}/orig${v.ext}`,prev:v.prev||"",hls:v.hls||"",poster:v.poster||""});
    if(v.owner===uid||adm)G.secs[v.id]=DB.secs[v.id]||0;
  }
  if(uid){G.cfg={card:DB.cfg.card,holder:DB.cfg.holder};G.stats[uid]=stats(uid);if(DB.mon[uid])G.mon[uid]=DB.mon[uid]}
  if(adm){for(const u of Object.keys(G.users)){G.stats[u]=stats(u);if(DB.mon[u])G.mon[u]=DB.mon[u]}}
  for(const[u,l]of Object.entries(DB.live)){G.live[u]={pub:l.pub,title:l.title};if(u===uid)G.live[u].key=l.pub+"?key="+l.secret}
  for(const w of DB.wd){if(adm)G.wd.push(w);else if(w.uid===uid)G.wd.push({id:w.id,uid:w.uid,amt:w.amt,c:w.c,st:w.st,ts:w.ts})}
  for(const p of DB.pay){
    if(adm){if(p.st==="chek"||p.st==="kutilmoqda")G.pay.push({...p,img:p.st==="chek"?`/media/p/${p.id}.jpg?s=${sigPay(p.id)}`:""});}
    else if(p.uid===uid)G.pay.push({id:p.id,uid:p.uid,type:p.type,plan:p.plan,vid:p.vid,usd:p.usd,ms:p.ms,l:p.l,ts:p.ts,dl:p.dl,st:p.st,why:p.why||"",sent:p.sent||0,img:""});
  }
  return{me:me&&me.ch?uid:"",authed:!!uid,admin:adm,G};
}

/* ---------- Amallar (op) ---------- */
const sampleId=s=>/^s\d{1,3}$/.test(s);
const chanOk=s=>(DB.users[s]&&DB.users[s].ch)||/^c-[a-z0-9-]{1,60}$/.test(s);
const vidExists=id=>!!DB.videos[id]||sampleId(id);
const needAdm=u=>{if(!isAdmin(u.uid))fail("forbidden",403)};
const OPS={
  channel(u,a){
    const ch=String(a.ch||"").trim().slice(0,30),user=String(a.user||"").toLowerCase();
    if(!ch)fail("ch_required");
    if(!/^[a-z0-9][a-z0-9-]{1,18}[a-z0-9]$/.test(user))fail("bad_handle");
    if(Object.values(DB.users).some(x=>x.user===user&&x.uid!==u.uid))fail("handle_taken",409);
    u.ch=ch;u.user=user;
    if(a.avatar!==undefined)u.avatar=imgField(a.avatar,u.avatar,"a",400e3);
    if(a.banner!==undefined)u.banner=imgField(a.banner,u.banner,"b",900e3);
  },
  sub(u,a){const ch=String(a.ch||"");if(!chanOk(ch))fail("no_channel",404);if(ch===u.uid)fail("self_sub");
    const m=DB.subs[ch]=DB.subs[ch]||{};if(m[u.uid])delete m[u.uid];else m[u.uid]=Date.now()},
  view(u,a,c){const id=String(a.vid||"");if(!vidExists(id))fail("no_video",404);const v=DB.videos[id];if(v&&v.owner===c.uid)return;
    if(!rl("vw:"+c.key,120,6e4))fail("rate",429);
    const m=DB.views[id]=DB.views[id]||{};if(!m[c.key])m[c.key]=Date.now()},
  watch(u,a,c){const id=String(a.vid||""),v=DB.videos[id];if(!v||v.kind!=="long"||v.owner===c.uid)return;
    const sec=Math.max(0,Math.min(30,+a.sec||0));if(!sec)return;if(!rl("wt:"+c.key+id,1,5e3))return;DB.secs[id]=(DB.secs[id]||0)+sec},
  like(u,a){const id=String(a.vid||"");if(!vidExists(id))fail("no_video",404);const m=DB.likes[id]=DB.likes[id]||{};if(a.on)m[u.uid]=Date.now();else delete m[u.uid]},
  comment(u,a){const id=String(a.vid||""),t=String(a.t||"").trim().slice(0,300);if(!vidExists(id))fail("no_video",404);if(!t)fail("empty");
    if(!rl("cm:"+u.uid,10,6e4))fail("rate",429);const arr=DB.cm[id]=DB.cm[id]||[];arr.push({n:u.ch||"Foydalanuvchi",u:u.uid,t,ts:Date.now()});if(arr.length>500)arr.shift()},
  "video.delete"(u,a){const v=DB.videos[String(a.id||"")];if(!v)fail("no_video",404);if(v.owner!==u.uid&&!isAdmin(u.uid))fail("forbidden",403);
    fs.rmSync(path.join(MEDIA,"v",v.id),{recursive:true,force:true});delete DB.videos[v.id];delete DB.views[v.id];delete DB.secs[v.id];delete DB.likes[v.id];delete DB.cm[v.id];delete DB.ads[v.id]},
  "mon.apply"(u){if(!u.ch)fail("ch_required");const mg=MG(u.uid);if(monActive(u.uid))fail("already_active");if(mg.pending)fail("already_pending");
    const s=stats(u.uid);mg.pending={ts:Date.now(),subs:s.subs,views:s.views,hrs:s.hrs};mg.rej=""},
  wd(u,a){const card=String(a.card||"").replace(/\s/g,""),amt=Math.floor(+a.amt||0);
    if(!/^\d{16}$/.test(card))fail("bad_card");if(amt<1e6)fail("min_amount");if(amt>1e7)fail("max_amount");
    if(!segsOf(u.uid).length)fail("not_monetized");const bal=Math.max(0,stats(u.uid).usd*RATE-paidOf(u.uid));if(amt>bal)fail("no_balance");
    DB.wd.unshift({id:rid(),uid:u.uid,amt,c:card.slice(-4),card,st:"Kutilmoqda",ts:Date.now()})},
  "pay.start"(u,a){const type=a.type==="ad"?"ad":"mon",P=(type==="mon"?PLANS:ADS)[a.plan];if(!P)fail("bad_plan");
    const vid=type==="ad"?String(a.vid||""):"";if(type==="ad"){const v=DB.videos[vid];if(!v||v.owner!==u.uid)fail("no_video",404)}
    expirePay();const ex=DB.pay.find(p=>p.uid===u.uid&&p.st==="kutilmoqda"&&p.type===type&&p.plan===a.plan&&p.vid===vid);
    if(ex)return{id:ex.id};
    const rec={id:rid(),uid:u.uid,type,plan:a.plan,vid,usd:P.usd,ms:P.ms,l:P.l,ts:Date.now(),dl:Date.now()+5*60000,st:"kutilmoqda"};DB.pay.unshift(rec);return{id:rec.id}},
  "pay.chek"(u,a){const p=DB.pay.find(x=>x.id===String(a.id||"")&&x.uid===u.uid);if(!p)fail("no_pay",404);expirePay();
    if(p.st!=="kutilmoqda")fail("pay_closed");saveImg(a.img,"p",p.id,1.5e6);p.st="chek";p.sent=Date.now()},
  "live.get"(u){DB.live[u.uid]=DB.live[u.uid]||{pub:crypto.randomBytes(6).toString("hex"),secret:crypto.randomBytes(12).toString("hex"),title:""}},
  "live.title"(u,a){const l=DB.live[u.uid];if(!l)fail("no_live",404);l.title=String(a.title||"").trim().slice(0,80)},
  "live.regen"(u){DB.live[u.uid]={pub:crypto.randomBytes(6).toString("hex"),secret:crypto.randomBytes(12).toString("hex"),title:(DB.live[u.uid]||{}).title||""}},
  /* --- admin --- */
  "mon.grant"(u,a){needAdm(u);if(!DB.users[a.uid])fail("no_user",404);const ms=+a.ms||0;if(ms<0||ms>3*365*DAY)fail("bad_ms");grant(a.uid,ms)},
  "mon.off"(u,a){needAdm(u);if(!DB.users[a.uid])fail("no_user",404);closeSegs(a.uid)},
  "mon.approve"(u,a){needAdm(u);if(!DB.users[a.uid])fail("no_user",404);grant(a.uid,0)},
  "mon.reject"(u,a){needAdm(u);if(!DB.users[a.uid])fail("no_user",404);const mg=MG(a.uid);mg.pending=null;mg.rej=String(a.why||"Shartlar yetarli emas").slice(0,120)},
  bonus(u,a){needAdm(u);const n=Math.floor(+a.n);if(!DB.users[a.uid]||!(n>0&&n<=1e7))fail("bad_args");DB.bonus[a.uid]=(DB.bonus[a.uid]||0)+n},
  "admin.add"(u,a){needAdm(u);const h=String(a.user||"").replace(/^@/,"").toLowerCase(),x=Object.values(DB.users).find(y=>y.user===h);if(!x)fail("no_user",404);if(!isAdmin(x.uid))DB.admins.push(x.uid)},
  "admin.rm"(u,a){needAdm(u);const x=DB.users[a.uid];if(!x)fail("no_user",404);if(x.user==="vidly")fail("forbidden",403);DB.admins=DB.admins.filter(i=>i!==a.uid)},
  "wd.set"(u,a){needAdm(u);const w=DB.wd.find(x=>x.id===a.id);if(!w)fail("no_wd",404);if(!["Toʻlangan","Rad etilgan"].includes(a.st))fail("bad_status");w.st=a.st},
  "cfg.card"(u,a){needAdm(u);const c=String(a.card||"").replace(/\D/g,"");if(c.length!==16)fail("bad_card");DB.cfg={card:c,holder:String(a.holder||"").trim().slice(0,60)}},
  "pay.approve"(u,a){needAdm(u);const p=DB.pay.find(x=>x.id===a.id);if(!p||p.st!=="chek")fail("no_pay",404);p.st="tasdiqlangan";if(p.type==="mon")extend(p.uid,p.ms);else extendAd(p.vid,p.ms)},
  "pay.reject"(u,a){needAdm(u);const p=DB.pay.find(x=>x.id===a.id);if(!p||p.st!=="chek")fail("no_pay",404);p.st="rad";p.why="Chek tasdiqlanmadi."}
};
const PUBLIC_OPS=new Set(["view","watch"]),QUIET=new Set(["view","watch","like","comment"]);

/* ---------- Yuklash va qayta kodlash ---------- */
function run(cmd,args,capture){return new Promise((ok,bad)=>{const p=spawn(cmd,args,{stdio:["ignore",capture?"pipe":"ignore","pipe"]});let out="",err="";if(capture)p.stdout.on("data",d=>{out+=d});p.stderr.on("data",d=>{err=(err+d).slice(-2000)});p.on("error",bad);p.on("close",c=>c===0?ok(out):bad(new Error(cmd+" exit "+c+": "+err.slice(-300))))})}
async function probe(file){
  try{
    const o=JSON.parse(await run("ffprobe",["-v","error","-select_streams","v:0","-show_entries","stream=width,height,duration:stream_tags=rotate:stream_side_data=rotation:format=duration","-of","json",file],true));
    const s=(o.streams||[])[0];if(!s||!s.width||!s.height)return null;
    let w=s.width,h=s.height;const rot=Math.abs(+((s.tags||{}).rotate||((s.side_data_list||[])[0]||{}).rotation||0));
    if(rot===90||rot===270)[w,h]=[h,w];
    return{w,h,dur:+(o.format&&o.format.duration)||+s.duration||0};
  }catch(e){return null}
}
const Q=[];let busy=false;
const queueT=id=>{Q.push(id);pump()};
async function pump(){if(busy)return;busy=true;while(Q.length){const id=Q.shift();try{await transcode(id)}catch(e){console.error("[transcode]",id,e.message);const v=DB.videos[id];if(v){v.status="ready";touch()}}}busy=false}
async function transcode(id){
  const v=DB.videos[id];if(!v)return;
  const dir=path.join(MEDIA,"v",id),src=path.join(dir,"orig"+v.ext),th=String(E.FFMPEG_THREADS||0),preset=E.FFMPEG_PRESET||"veryfast";
  try{await run("ffmpeg",["-y","-ss",String(Math.min(1,(v.dur||0)/2)),"-i",src,"-frames:v","1","-vf","scale=640:-2","-q:v","4",path.join(dir,"poster.jpg")]);v.poster=`/media/v/${id}/poster.jpg`;touch()}catch(e){}
  const portrait=v.ww<=v.hh,short=Math.min(v.ww,v.hh),sc=h=>portrait?`scale=${h}:-2`:`scale=-2:${h}`;
  const pv=Math.min(short,480);
  try{await run("ffmpeg",["-y","-i",src,"-vf",sc(pv),"-c:v","libx264","-preset",preset,"-crf","28","-pix_fmt","yuv420p","-c:a","aac","-b:a","96k","-movflags","+faststart","-threads",th,path.join(dir,"prev.mp4")]);v.prev=`/media/v/${id}/prev.mp4`;touch()}catch(e){console.error("[prev]",id,e.message)}
  let L=[[360,800],[480,1400],[720,2800],[1080,5000],[1440,8000],[2160,14000]].filter(x=>x[0]<=short+8);
  if(!L.length)L=[[short,Math.max(300,short*2)]];
  const out=[];
  for(const[h,br]of L){
    const d=path.join(dir,h+"p");fs.mkdirSync(d,{recursive:true});
    await run("ffmpeg",["-y","-i",src,"-vf",sc(h),"-c:v","libx264","-preset",preset,"-profile:v","high","-b:v",br+"k","-maxrate",Math.round(br*1.1)+"k","-bufsize",br*2+"k","-g","48","-keyint_min","48","-sc_threshold","0","-pix_fmt","yuv420p","-c:a","aac","-b:a","128k","-ac","2","-threads",th,"-f","hls","-hls_time","4","-hls_playlist_type","vod","-hls_segment_filename",path.join(d,"s%04d.ts"),path.join(d,"index.m3u8")]);
    const w=portrait?h:Math.round(v.ww*h/v.hh/2)*2,hh=portrait?Math.round(v.hh*h/v.ww/2)*2:h;
    out.push({h,br,w,hh});
    fs.writeFileSync(path.join(dir,"master.m3u8"),"#EXTM3U\n#EXT-X-VERSION:3\n"+out.map(o=>`#EXT-X-STREAM-INF:BANDWIDTH=${(o.br+128)*1000},RESOLUTION=${o.w}x${o.hh},NAME="${o.h}p"\n${o.h}p/index.m3u8`).join("\n")+"\n");
    v.hls=`/media/v/${id}/master.m3u8`;touch();
  }
  v.status="ready";touch();
}
async function upload(req,res,uid){
  const u=DB.users[uid];if(!u||!u.ch)fail("channel_required",403);
  if(!rl("up:"+uid,20,36e5))fail("rate",429);
  const q=new URL(req.url,"http://x").searchParams,title=(q.get("title")||"").trim().slice(0,80);if(!title)fail("title_required");
  const cat=CATS.includes(q.get("c"))?q.get("c"):"Kulgi",ext=(path.extname(q.get("name")||"").toLowerCase());
  if(![".mp4",".mov",".webm",".mkv",".m4v",".3gp"].includes(ext))fail("bad_format",415);
  const len=+req.headers["content-length"]||0;if(len>MAXB)fail("too_large",413);
  const id="u"+Date.now().toString(36)+crypto.randomBytes(2).toString("hex"),dir=path.join(MEDIA,"v",id);
  fs.mkdirSync(dir,{recursive:true});const file=path.join(dir,"orig"+ext);let n=0,bad=null;
  const ws=fs.createWriteStream(file);
  req.on("data",c=>{n+=c.length;if(n>MAXB&&!bad){bad=Object.assign(new Error("too_large"),{status:413});req.unpipe(ws);ws.destroy();req.resume()}});
  try{await new Promise((ok,ko)=>{ws.on("finish",ok);ws.on("error",ko);req.on("error",ko);req.on("aborted",()=>ko(new Error("aborted")));req.pipe(ws)})}catch(e){}
  if(bad||req.aborted||!n){fs.rmSync(dir,{recursive:true,force:true});throw bad||Object.assign(new Error("upload_failed"),{status:400})}
  const info=await probe(file);
  if(!info){fs.rmSync(dir,{recursive:true,force:true});fail("not_video",415)}
  const kind=info.w<=info.h?"short":"long";
  DB.videos[id]={id,t:title,c:cat,owner:uid,kind,dur:info.dur,ts:Date.now(),adult:q.get("adult")==="1",ww:info.w,hh:info.h,status:"processing",ext,hls:"",prev:"",poster:""};touch();
  json(res,200,{ok:true,id,kind});queueT(id);
}

/* ---------- API ---------- */
async function api(req,res,p){
  const uid=auth(req),key=vkey(req,uid),M=req.method;
  if(p==="/api/health")return json(res,200,{ok:true});
  if(p==="/api/state"&&M==="GET")return json(res,200,view(uid,key));
  if(p==="/api/auth/sms/send"&&M==="POST"){
    const b=await readJson(req),phone=String(b.phone||"").replace(/\D/g,"");
    if(!okPhone(phone))fail("bad_phone");
    if(!rl("sp:"+phone,3,6e5)||!rl("si:"+ipOf(req),10,36e5))fail("rate",429);
    const code=String(crypto.randomInt(100000,1000000));
    DB.sms[phone]={h:hashCode(phone,code),exp:Date.now()+5*60000,tries:0};
    try{await sendSms(phone,code)}catch(e){delete DB.sms[phone];if(e.status)throw e;console.error("[sms]",e.message);fail("sms_failed",502)}
    touch();return json(res,200,{ok:true});
  }
  if(p==="/api/auth/sms/verify"&&M==="POST"){
    const b=await readJson(req),phone=String(b.phone||"").replace(/\D/g,""),code=String(b.code||"").replace(/\D/g,""),r=DB.sms[phone];
    if(!okPhone(phone)||!r||r.exp<Date.now())fail("code_expired",400);
    if(++r.tries>5){delete DB.sms[phone];touch();fail("too_many_tries",429)}
    const h=hashCode(phone,code);if(h.length!==r.h.length||!crypto.timingSafeEqual(Buffer.from(h),Buffer.from(r.h))){touch();fail("bad_code",400)}
    delete DB.sms[phone];
    let u=Object.values(DB.users).find(x=>x.phone===phone);
    if(!u){u=DB.users[rid()]={uid:"",phone,phoneOk:true,ch:"",user:"",avatar:"",banner:"",ts:Date.now()};u.uid=Object.keys(DB.users).find(k=>DB.users[k]===u)}
    touch();
    const token=sign({uid:u.uid,exp:Math.floor(Date.now()/1e3)+30*86400});
    return json(res,200,{ok:true,token,state:view(u.uid,u.uid)});
  }
  if(p==="/api/op"&&M==="POST"){
    const b=await readJson(req),fn=OPS[b.op];if(!fn)fail("bad_op",404);
    if(!PUBLIC_OPS.has(b.op)&&!uid)fail("auth_required",401);
    if(!rl("op:"+key,300,6e4))fail("rate",429);
    const u=DB.users[uid],r=fn(u,b,{uid,key});touch();
    const o={ok:true,res:r||{}};if(!QUIET.has(b.op))o.state=view(uid,key);
    return json(res,200,o);
  }
  if(p==="/api/upload"&&M==="PUT"){if(!uid)fail("auth_required",401);return await upload(req,res,uid)}
  if(p==="/api/live/auth"&&M==="POST"){
    const b=await readJson(req,1e5);
    if(b.action==="read"||b.action==="playback"||b.action==="api"&&false)return json(res,200,{});
    if(b.action==="publish"){
      const q=new URLSearchParams(String(b.query||"")),k=q.get("key")||"";
      const l=Object.values(DB.live).find(x=>x.pub===b.path);
      if(l&&k&&k.length===l.secret.length&&crypto.timingSafeEqual(Buffer.from(k),Buffer.from(l.secret)))return json(res,200,{});
    }
    return json(res,401,{});
  }
  fail("not_found",404);
}

/* ---------- Statik fayllar ---------- */
const MIME={".html":"text/html; charset=utf-8",".js":"text/javascript; charset=utf-8",".css":"text/css",".json":"application/json",".jpg":"image/jpeg",".jpeg":"image/jpeg",".png":"image/png",".webp":"image/webp",".svg":"image/svg+xml",".mp4":"video/mp4",".m4v":"video/mp4",".mov":"video/quicktime",".webm":"video/webm",".mkv":"video/x-matroska",".3gp":"video/3gpp",".m3u8":"application/vnd.apple.mpegurl",".ts":"video/mp2t",".ico":"image/x-icon"};
function serveFile(req,res,file,cache){
  fs.stat(file,(err,st)=>{
    if(err||!st.isFile()){res.writeHead(404);return res.end("Not found")}
    const h={"Content-Type":MIME[path.extname(file).toLowerCase()]||"application/octet-stream","Accept-Ranges":"bytes","Cache-Control":cache||"no-cache","X-Content-Type-Options":"nosniff"};
    const r=req.headers.range,m=r&&/^bytes=(\d*)-(\d*)$/.exec(r);
    if(m){
      let s=m[1]?+m[1]:0,e=m[2]?+m[2]:st.size-1;if(!m[1]&&m[2]){s=Math.max(0,st.size-+m[2]);e=st.size-1}
      if(s>e||s>=st.size){res.writeHead(416,{"Content-Range":"bytes */"+st.size});return res.end()}
      e=Math.min(e,st.size-1);res.writeHead(206,{...h,"Content-Range":`bytes ${s}-${e}/${st.size}`,"Content-Length":e-s+1});
      return fs.createReadStream(file,{start:s,end:e}).on("error",()=>res.destroy()).pipe(res);
    }
    res.writeHead(200,{...h,"Content-Length":st.size});
    if(req.method==="HEAD")return res.end();
    fs.createReadStream(file).on("error",()=>res.destroy()).pipe(res);
  });
}
function inside(base,f){return f===base||f.startsWith(base+path.sep)}
function serveMedia(req,res,p,u){
  let rel;try{rel=decodeURIComponent(p.slice(7))}catch(e){res.writeHead(400);return res.end()}
  const f=path.resolve(MEDIA,rel);if(!inside(MEDIA,f)){res.writeHead(403);return res.end()}
  if(rel.startsWith("p/")){const id=path.basename(rel,path.extname(rel));if(u.searchParams.get("s")!==sigPay(id)){res.writeHead(403);return res.end()}return serveFile(req,res,f,"private, max-age=3600")}
  serveFile(req,res,f,/master\.m3u8$/.test(rel)?"no-cache":"public, max-age=31536000, immutable");
}
function serveStatic(req,res,p){
  if(p==="/config.js"){res.writeHead(200,{"Content-Type":"text/javascript; charset=utf-8","Cache-Control":"no-cache"});return res.end("window.VIDLY_CONFIG="+JSON.stringify({SERVER:true,API_URL:"",RTMP_URL:E.RTMP_URL||"",HLS_BASE:E.HLS_BASE||""})+";")}
  let rel;try{rel=decodeURIComponent(p)}catch(e){res.writeHead(400);return res.end()}
  if(rel==="/")rel="/index.html";
  const f=path.resolve(PUB,"."+rel);if(!inside(PUB,f)){res.writeHead(403);return res.end()}
  serveFile(req,res,f,"no-cache");
}
function cors(req,res){
  res.setHeader("X-Content-Type-Options","nosniff");res.setHeader("Referrer-Policy","same-origin");
  const o=req.headers.origin;
  if(ORIGIN&&o&&(ORIGIN==="*"||o===ORIGIN)){res.setHeader("Access-Control-Allow-Origin",ORIGIN==="*"?"*":o);res.setHeader("Vary","Origin");res.setHeader("Access-Control-Allow-Headers","Authorization, Content-Type, X-Viewer");res.setHeader("Access-Control-Allow-Methods","GET,POST,PUT,OPTIONS")}
}
const server=http.createServer(async(req,res)=>{
  try{
    const u=new URL(req.url,"http://x"),p=u.pathname;
    cors(req,res);
    if(req.method==="OPTIONS"){res.writeHead(204);return res.end()}
    if(p.startsWith("/api/"))return await api(req,res,p);
    if(p.startsWith("/media/"))return serveMedia(req,res,p,u);
    return serveStatic(req,res,p);
  }catch(e){
    const st=e.status||500;if(st===500)console.error(e);
    if(!res.headersSent)json(res,st,{err:e.status?e.message:"server_error"});else res.destroy();
  }
});
server.requestTimeout=0;server.headersTimeout=60000;
server.listen(PORT,()=>console.log("Vidly server: http://localhost:"+PORT+"  (ma'lumotlar: "+DATA+")"));
// Qayta ishga tushganda yarim qolgan videolarni davom ettirish
for(const v of Object.values(DB.videos))if(v.status==="processing")queueT(v.id);
