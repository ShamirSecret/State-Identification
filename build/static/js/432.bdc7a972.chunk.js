"use strict";(self.webpackChunknew_picwe=self.webpackChunknew_picwe||[]).push([[432,844,402],{2844:(e,a,s)=>{s.r(a),s.d(a,{default:()=>d});var t=s(2791),r=s(5533),i=s(43),n=s(9230),l=s(8926),o=s(1991),c=s(184);const d=function(){const{t:e,i18n:a}=(0,n.$G)(),{message:s}=r.Z.useApp(),[d,m]=(0,l.o)(),[u,p]=(0,t.useState)([]),h=e=>{if(isNaN(e))return e;e=""+e;let a=(e=parseFloat(e)).toExponential().match(/\d(?:\.(\d*))?e([+-]\d+)/);return e.toFixed(Math.max(0,(a[1]||"").length-a[2]))};let x=!1;(0,t.useEffect)((()=>(async function(){x||d.userName&&(async()=>{try{await o.W.get("/point_trade/get_user_assets").then((e=>{p(e.data.assets)}))}catch(e){console.log(e)}})()}(),()=>{x=!0})),[]);const g=()=>d.userName?(0,c.jsx)("div",{className:"loading",children:(0,c.jsx)(i.Z,{size:"large"})}):(0,c.jsx)(c.Fragment,{});return(0,c.jsx)("div",{className:"db-table-main",children:u&&u.length>0?u.map(((e,a)=>(0,c.jsxs)("div",{className:1==u.length?"table-points-oneinfo":"table-points-info",children:[(0,c.jsx)("div",{className:"table-points",children:e.symbol}),(0,c.jsx)("div",{className:"table-points",children:h(e.quantity)})]},a))):(0,c.jsx)(g,{})})}},2432:(e,a,s)=>{s.r(a),s.d(a,{default:()=>k});var t=s(2791),r=s(9230),i=s(5533),n=s(959),l=s(8526),o=s(2641),c=s(4102),d=s(8598),m=s(7106),u=s(9286),p=s(1994),h=s(1991),x=s(8926),g=s(184);function j(e){const{t:a,i18n:s}=(0,r.$G)(),{width:j,height:f}=(0,d.Z)(),{perVisible:y,operDialogPer:v}=e,[b,N]=(0,x.o)(),{message:Z}=i.Z.useApp(),[w,k]=(0,t.useState)(!1),[P,C]=(0,t.useState)(),[$,I]=(0,t.useState)([]),S=(e,a)=>{const s=new FileReader;s.addEventListener("load",(()=>a(s.result))),s.readAsDataURL(e)},_=(0,g.jsxs)("div",{children:[w?(0,g.jsx)(m.Z,{}):(0,g.jsx)(u.Z,{}),P?(0,g.jsx)("img",{src:c}):(0,g.jsx)("div",{style:{marginTop:8},children:"Upload"})]}),A=async e=>{try{await h.B.put("/update_avatar",e).then((e=>{200!=e.data.code?Z.error(e.data.message):(v(!1),Z.success(`${a("SubmitTrue")}`),I([]),N({type:"upAvatar",userAvatar:e.data.data.filename}),localStorage.setItem("userAvatar",e.data.data.filename))}))}catch(s){console.log(s)}};return(0,t.useEffect)((()=>{(()=>{const e="null"==b.userAvatar?c:b.url+b.userAvatar;C(e)})()}),[]),(0,g.jsx)(n.Z,{open:y,onCancel:()=>{v(!1)},footer:[],children:(0,g.jsxs)(l.Z,{name:"editper",labelCol:{span:5},wrapperCol:{span:16},style:{maxWidth:600},onFinish:e=>{const s=new FormData;$.forEach((e=>{s.append("avatar",e)})),$.length>0?A(s):Z.error(`${a("ErrorAvatar")}`)},onFinishFailed:e=>{console.log("Failed:",e)},autoComplete:"off",children:[(0,g.jsx)(l.Z.Item,{label:a("Avatar"),name:"avatar",children:(0,g.jsx)(l.Z.Item,{name:"dragger",valuePropName:"fileList",getValueFromEvent:e=>Array.isArray(e)?e:null===e||void 0===e?void 0:e.fileList,noStyle:!0,children:(0,g.jsx)(p.Z,{name:"avatar",listType:"picture-circle",showUploadList:!1,maxCount:1,beforeUpload:e=>{if(!("image/jpeg"===e.type||"image/png"===e.type))return void Z.error(`${a("YCImg")}`);if(e.size/1024/1024<2)return S(e,(e=>{k(!1),C(e)})),I([e]),!1;Z.error(`${a("YCImgSize")}`)},onChange:e=>{"uploading"!==e.file.status?"done"===e.file.status&&S(e.file.originFileObj,(e=>{k(!1),C(e)})):k(!0)},children:P?(0,g.jsx)("img",{src:P,alt:"avatar",style:{width:"100%"}}):_})})}),j>767?(0,g.jsx)(l.Z.Item,{wrapperCol:{offset:5,span:16},children:(0,g.jsx)(o.ZP,{type:"primary",htmlType:"submit",children:a("Submit")})}):(0,g.jsx)(l.Z.Item,{wrapperCol:{offset:0,span:16},children:(0,g.jsx)(o.ZP,{type:"primary",htmlType:"submit",children:a("Submit")})})]})})}var f=s(8737);function y(e){const{t:a,i18n:s}=(0,r.$G)(),{width:t,height:c}=(0,d.Z)(),{nicknameVisible:m,operDialogNickname:u}=e,[p,j]=(0,x.o)(),{message:y}=i.Z.useApp(),v=async e=>{try{await h.W.put("/update_nickname",e).then((s=>{200!=s.data.code?y.error(s.data.message):(j({type:"upNickname",userNickname:e.nickname}),localStorage.setItem("userNickname",e.nickname),u(!1),y.success(`${a("SubmitTrue")}`))}))}catch(s){console.log(s)}};return(0,g.jsx)(n.Z,{open:m,onCancel:()=>{u(!1)},footer:[],children:(0,g.jsxs)(l.Z,{name:"editNickname",labelCol:{span:5},wrapperCol:{span:16},style:{maxWidth:600},onFinish:e=>{v(e)},onFinishFailed:e=>{console.log("Failed:",e)},autoComplete:"off",children:[(0,g.jsx)(l.Z.Item,{label:a("Nickname"),name:"nickname",rules:[{required:!0,message:`${a("Required")}`},{validator:async(e,s)=>{if(!s)return Promise.resolve();return/^\w{2,16}$/.test(s)?Promise.resolve():Promise.reject(`${a("formatNickname")}`)}}],children:(0,g.jsx)(f.Z,{})}),t>767?(0,g.jsxs)(l.Z.Item,{wrapperCol:{offset:5,span:16},children:[(0,g.jsx)(o.ZP,{type:"primary",htmlType:"submit",children:a("Submit")}),(0,g.jsx)(o.ZP,{htmlType:"reset",children:a("reset")})]}):(0,g.jsxs)(l.Z.Item,{wrapperCol:{offset:0,span:16},children:[(0,g.jsx)(o.ZP,{type:"primary",htmlType:"submit",children:a("Submit")}),(0,g.jsx)(o.ZP,{htmlType:"reset",children:a("reset")})]})]})})}function v(e){const{t:a,i18n:s}=(0,r.$G)(),{width:c,height:m}=(0,d.Z)(),{passwordVisible:u,operDialogPassword:p}=e,[j,y]=(0,x.o)(),v=t.useRef(null),{message:b}=i.Z.useApp(),N=async(e,s)=>{if(!s)return Promise.resolve();return/^(?=.*[0-9])(?=.*[a-zA-Z])[a-zA-Z0-9]{8,18}$/.test(s)?Promise.resolve():Promise.reject(`${a("formatPassword")}`)},Z=async e=>{try{await h.W.post("/change_password",e).then((e=>{var s;200!=e.data.code?b.error(e.data.message):(null===(s=v.current)||void 0===s||s.resetFields(),p(!1),b.success(`${a("SubmitTrue")}`))}))}catch(s){console.log(s)}};return(0,g.jsx)(n.Z,{open:u,onCancel:()=>{p(!1)},footer:[],children:(0,g.jsxs)(l.Z,{ref:v,name:"editPassword",labelCol:{span:5},wrapperCol:{span:16},style:{maxWidth:600},onFinish:e=>{Z(e)},onFinishFailed:e=>{console.log("Failed:",e)},autoComplete:"off",children:[(0,g.jsx)(l.Z.Item,{label:a("OldPassword"),name:"old_password",rules:[{required:!0,message:`${a("Required")}`},{validator:N}],children:(0,g.jsx)(f.Z.Password,{})}),(0,g.jsx)(l.Z.Item,{label:a("NewPassword"),name:"new_password",rules:[{required:!0,message:`${a("Required")}`},{validator:N}],children:(0,g.jsx)(f.Z.Password,{})}),c>767?(0,g.jsxs)(l.Z.Item,{wrapperCol:{offset:5,span:16},children:[(0,g.jsx)(o.ZP,{type:"primary",htmlType:"submit",children:a("Submit")}),(0,g.jsx)(o.ZP,{htmlType:"reset",children:a("reset")})]}):(0,g.jsxs)(l.Z.Item,{wrapperCol:{offset:0,span:16},children:[(0,g.jsx)(o.ZP,{type:"primary",htmlType:"submit",children:a("Submit")}),(0,g.jsx)(o.ZP,{htmlType:"reset",children:a("reset")})]})]})})}var b=s(1932),N=s(5881),Z=s(2844),w=s(9402);const k=function(){const{t:e,i18n:a}=(0,r.$G)(),[s,n]=(0,t.useState)(!1),[l,o]=(0,t.useState)(!1),[d,m]=(0,t.useState)(!1),[u,p]=(0,x.o)(),{message:f,modal:k}=i.Z.useApp(),[P,C]=(0,t.useState)("1"),$=[{key:"1",label:`${e("integral")}`,children:(0,g.jsx)(Z.default,{})},{key:"2",label:`${e("myorder")}`,children:(0,g.jsx)(w.default,{})}],I=e=>{n(e)},S=e=>{o(e)},_=e=>{m(e)};let A=!1;return(0,t.useEffect)((()=>(async function(){A||(u.userId&&null==u.Icode&&((async e=>{if(null!=e)try{await h.W.get("/getuserinfo/"+e).then((e=>{200==e.data.code&&(p({type:"upAvatar",userAvatar:e.data.data.info.avatar_image_filename}),localStorage.setItem("userAvatar",e.data.data.info.avatar_image_filename),p({type:"upNickname",userNickname:e.data.data.info.avatar_name}),localStorage.setItem("userNickname",e.data.data.info.avatar_name))}))}catch(a){console.log(a)}})(u.userId),(async()=>{try{await h.W.get("/invitation_code").then((e=>{200!=e.data.code?f.error(e.data.message):(p({type:"upIcode",Icode:e.data.data.invitation_code}),localStorage.setItem("Icode",e.data.data.invitation_code))}))}catch(e){console.log(e)}})()),1==u.chartName.length&&C(u.chartName))}(),()=>{A=!0})),[]),(0,g.jsxs)("div",{className:"index-content",children:[(0,g.jsxs)("div",{className:"personal-information",children:[(0,g.jsx)("div",{className:"personal-img",children:null!=u.userAvatar?(0,g.jsx)("img",{src:u.url+u.userAvatar,alt:""}):(0,g.jsx)("img",{src:c,alt:""})}),(0,g.jsx)("div",{className:"personal-name",children:(0,g.jsxs)("span",{children:[" ","Default Nickname"==u.userNickname?u.userName:u.userNickname," "]})}),(0,g.jsxs)("div",{className:"personal-button",children:[(0,g.jsx)("span",{onClick:()=>{null!=u.userId?S(!0):f.error(`${e("ErrorUser")}`)},children:e("editNickname")}),(0,g.jsx)("span",{onClick:()=>{null!=u.userId?I(!0):f.error(`${e("ErrorUser")}`)},children:e("editAvatar")}),(0,g.jsx)("span",{onClick:()=>{null!=u.userId?_(!0):f.error(`${e("ErrorUser")}`)},children:e("editPassword")})]})]}),(0,g.jsx)("div",{className:"personal-tabs",children:(0,g.jsx)(b.ZP,{theme:{token:{colorPrimary:"#f9e296"}},children:(0,g.jsx)(N.Z,{items:$,onChange:e=>{C(e),"3"==e&&(p({type:"upChartName",chartName:e}),p({type:"upChartPage",chartPage:1}),p({type:"upBackUrl",backUrl:"/my"}))},activeKey:P})})}),(0,g.jsx)(j,{perVisible:s,operDialogPer:I}),(0,g.jsx)(y,{nicknameVisible:l,operDialogNickname:S}),(0,g.jsx)(v,{passwordVisible:d,operDialogPassword:_})]})}},9402:(e,a,s)=>{s.r(a),s.d(a,{default:()=>c});var t=s(2791),r=s(5533),i=s(9230),n=s(8926),l=s(1991),o=s(184);const c=function(){const{t:e,i18n:a}=(0,i.$G)(),{message:s}=r.Z.useApp(),[c,d]=(0,n.o)(),[m,u]=(0,t.useState)([]);let p=!1;return(0,t.useEffect)((()=>(async function(){p||c.userName&&(async()=>{try{await l.W.get("/point_trade/get_user_orders").then((e=>{u(e.data.orders)}))}catch(e){console.log(e)}})()}(),()=>{p=!0})),[]),(0,o.jsx)("div",{className:"db-table-main",children:c.userName?(0,o.jsx)(o.Fragment,{children:m&&m.length>0&&m.map(((a,s)=>(0,o.jsxs)("div",{className:"list-item-info",children:[(0,o.jsxs)("div",{className:"item-title",children:[e("sideType"),"\uff1a","buy"==a.side?`${e("limitBuy")}`:`${e("limitSell")}`]}),(0,o.jsxs)("div",{className:"item-title",children:[e("token"),"\uff1a",a.symbol]}),(0,o.jsxs)("div",{className:"item-title",children:[e("Isitadeal"),"\uff1a",0==a.has_matched?`${e("transactionF")}`:`${e("transactionT")}`]}),(0,o.jsxs)("div",{className:"item-title",children:[e("tradingvolume"),"\uff1a",a.filled_quantity]}),(0,o.jsxs)("div",{className:"item-title",children:[e("Price"),"\uff1a",a.price]}),(0,o.jsxs)("div",{className:"item-title",children:[e("pricingType"),"\uff1a","limit"==a.order_type?`${e("limittorder")}`:`${e("marketorder")}`]}),(0,o.jsx)("div",{className:"item-foot",children:(0,o.jsx)("span",{className:"db-table-time",children:a.timestamp})})]},s)))}):(0,o.jsx)(o.Fragment,{})})}}}]);
//# sourceMappingURL=432.bdc7a972.chunk.js.map