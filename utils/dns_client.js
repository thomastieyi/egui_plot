var dns = require('native-dns');
// var util = require('util');

var question = dns.Question({
  name: 'www.google.com',
  type: 'AAAA',
});

var start = Date.now();

var req = dns.Request({
  question: question,
  server: { address: '127.0.0.1', port: 53, type: 'udp' },
  timeout: 1000,
});

req.on('timeout', function () {
  console.log('Timeout in making request');
});

req.on('message', function (err, answer) {
  answer.answer.forEach(function (a) {
    console.log(a.address);
  });
});

req.on('end', function () {
  var delta = (Date.now()) - start;
  console.log('Finished processing request: ' + delta.toString() + 'ms');
});

req.send();