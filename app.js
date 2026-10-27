/* Oriventa Markets: shared front-end helpers.
   IMPORTANT: this is a FRONT-END DEMO. Accounts are kept in this browser's localStorage so the
   flow (sign up -> login -> dashboard) can be reviewed. Passwords are stored only as salted PBKDF2
   hashes, but a real product MUST do registration, login and sessions on a secure server instead.
   Replace the Store methods below with calls to your backend API. */
(function(){
 var yr=document.getElementById('yr');if(yr)yr.textContent=new Date().getFullYear();
 var p=location.pathname.split('/').pop()||'index.html';
 var map={'index.html':'index','login.html':'login','signup.html':'signup','dashboard.html':''};
 var on=map[p];
 document.querySelectorAll('#nav a[data-p]').forEach(function(a){if(a.dataset.p===on)a.classList.add('on')});
 // logged-in users: swap Log in / Sign up for Dashboard
 try{if(sessionStorage.getItem('oriventa_session')){var n=document.getElementById('nav');
  if(n)n.querySelectorAll('a[data-p="login"],a[data-p="signup"]').forEach(function(a){a.remove()});
  if(n){var d=document.createElement('a');d.href='dashboard.html';d.className='cta';d.textContent='Dashboard';n.appendChild(d)}}}catch(e){}
})();

var Store={
 KEY:'oriventa_users_v1',SES:'oriventa_session',
 users:function(){try{return JSON.parse(localStorage.getItem(this.KEY))||[]}catch(e){return []}},
 _save:function(u){try{localStorage.setItem(this.KEY,JSON.stringify(u))}catch(e){throw new Error('Your browser blocked storage. Turn off private mode or allow site data.')}},
 _b64:function(buf){var s='';new Uint8Array(buf).forEach(function(b){s+=String.fromCharCode(b)});return btoa(s)},
 _unb64:function(t){return Uint8Array.from(atob(t),function(c){return c.charCodeAt(0)})},
 _hash:async function(pw,salt){
  if(!window.crypto||!crypto.subtle)throw new Error('Secure crypto is unavailable. Open this site over HTTPS.');
  var k=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveBits']);
  var bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:salt,iterations:200000,hash:'SHA-256'},k,256);
  return this._b64(bits)},
 createUser:async function(d){
  var list=this.users(),un=d.username.toLowerCase(),em=d.email.toLowerCase();
  if(list.some(function(x){return x.username.toLowerCase()===un}))throw new Error('That username is already taken. Please choose another.');
  if(list.some(function(x){return x.email.toLowerCase()===em}))throw new Error('An account with that email already exists. Please log in instead.');
  var salt=crypto.getRandomValues(new Uint8Array(16));
  list.push({fullName:d.fullName,username:d.username,email:em,wallets:d.wallets,salt:this._b64(salt),hash:await this._hash(d.password,salt),
   acceptedTerms:true,acceptedAt:d.acceptedAt,createdAt:new Date().toISOString()});
  this._save(list)},
 login:async function(id,pw){
  var key=id.trim().toLowerCase(),u=this.users().find(function(x){return x.username.toLowerCase()===key||x.email===key});
  if(!u)return {status:'nouser'};
  var h=await this._hash(pw,this._unb64(u.salt));
  return h===u.hash?{status:'ok',user:u}:{status:'badpw'}},
 setSession:function(un){try{sessionStorage.setItem(this.SES,un)}catch(e){}},
 currentUser:function(){try{var un=sessionStorage.getItem(this.SES);return this.users().find(function(x){return x.username===un})||null}catch(e){return null}},
 logout:function(){try{sessionStorage.removeItem(this.SES)}catch(e){}}
};
