var dns = require('native-dns');
var dns_server = dns.createServer();
var udp = require('dgram');

var pcscf_addr = "240e:66:1000::424"

// --------------------creating a udp server --------------------

// creating a udp server
var server = udp.createSocket('udp4');

// emits when any error occurs
server.on('error',function(error){
  console.log('Error: ' + error);
  server.close();
});

// emits on new datagram msg
server.on('message',function(msg,info){
  console.log('PCSCF_V6 ' + msg.toString());
  pcscf_addr = msg.toString()

//sending msg
// server.send(msg,info.port,'localhost',function(error){
//   if(error){
//     client.close();
//   }else{
//     console.log('Data sent !!!');
//   }

// });

});

//emits when socket is ready and listening for datagram msgs
server.on('listening',function(){
  var address = server.address();
  var port = address.port;
  var family = address.family;
  var ipaddr = address.address;
  console.log('Server is listening at port' + port);
  console.log('Server ip :' + ipaddr);
  console.log('Server is IP4/IP6 : ' + family);
});

//emits after the socket is closed using socket.close();
server.on('close',function(){
  console.log('Socket is closed !');
});

server.bind(2222);


dns_server.on('request', function (request, response) {
  //console.log(request)
  response.answer.push(dns.AAAA({
    name: request.question[0].name,
    address: pcscf_addr,
    ttl: 600,
  }));

  response.send();
});

dns_server.on('error', function (err, buff, req, res) {
  console.log(err.stack);
});

dns_server.serve(53);