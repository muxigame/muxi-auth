'use strict';
const $=(id)=>document.getElementById(id);
async function api(path,options={}){const response=await fetch(path,{...options,headers:{'Content-Type':'application/json',...(options.headers||{})}});let body={};try{body=await response.json()}catch{}if(!response.ok)throw new Error(body.detail||body.error_description||'请求失败');return body}
function showMessage(text,error=false){const el=$('message');if(!el)return;el.textContent=text;el.classList.toggle('error',error);el.hidden=false}
function continueTarget(){const value=new URLSearchParams(location.search).get('continue')||'/account';return value.startsWith('/')&&!value.startsWith('//')?value:'/account'}
function continueQuery(){return encodeURIComponent(continueTarget())}
function clientLabel(){
  try{
    const target=new URL(continueTarget(),location.origin);
    if(target.pathname!=='/oauth/authorize')return '';
    const client=target.searchParams.get('client_id');
    if(client==='better-mc-launcher')return 'Better MC Launcher';
    if(client==='better-mc-web')return 'Better MC';
  }catch{}
  return '';
}
function wireAuthContext(){
  const client=clientLabel();
  const context=$('auth-context');
  if(context&&client){context.textContent=`继续使用 ${client}`;context.hidden=false}
  document.querySelectorAll('[data-preserve-continue]').forEach(link=>{
    const base=link.getAttribute('href').split('?')[0];
    link.href=`${base}?continue=${continueQuery()}`;
  });
}
async function loadAccount(){try{const {user}=await api('/api/account/me');if($('username'))$('username').textContent=user.username;if($('email'))$('email').textContent=user.email;if($('role'))$('role').textContent=user.role;if($('created'))$('created').textContent=new Date(user.createdAt).toLocaleString('zh-CN')}catch{if(location.pathname==='/account')location.href='/login?continue=%2Faccount'}}
if($('login-form')){$('login-form').onsubmit=async(e)=>{e.preventDefault();const form=Object.fromEntries(new FormData(e.currentTarget));try{await api('/api/account/login',{method:'POST',body:JSON.stringify(form)});location.href=continueTarget()}catch(err){showMessage(err.message,true)}};const verified=new URLSearchParams(location.search).get('verified');if(verified)showMessage(verified==='1'?'邮箱验证完成。请登录以继续。':'验证链接无效或已经过期。',verified!=='1');wireAuthContext()}
if($('register-form')){$('register-form').onsubmit=async(e)=>{e.preventDefault();const form=Object.fromEntries(new FormData(e.currentTarget));try{const result=await api(`/api/account/register?continue_to=${continueQuery()}`,{method:'POST',body:JSON.stringify(form)});showMessage(result.message);if(result.verificationUrl){const a=document.createElement('a');a.href=result.verificationUrl;a.textContent=' 开发模式：立即验证';a.style.marginLeft='8px';$('message').appendChild(a)}e.currentTarget.reset()}catch(err){showMessage(err.message,true)}};wireAuthContext()}
if($('logout')){$('logout').onclick=async()=>{await api('/api/account/logout',{method:'POST'});location.href='/login'};loadAccount()}

