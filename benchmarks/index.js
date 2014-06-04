var assert = require('assert');
var benchmark = require('benchmark');
var hash = require('hash.js');
var elliptic = require('../');
var eccjs = require('eccjs');
var jodid = require('./deps/jodid');

var benchmarks = [];
var maxTime = 10;

function add(op, obj) {
  benchmarks.push({
    name: op,
    start: function start() {
      var suite = new benchmark.Suite;

      console.log('Benchmarking: ' + op);
      Object.keys(obj).forEach(function(key) {
        suite.add(key + '#' + op, obj[key], { maxTime: maxTime })
      });

      suite
        .on('cycle', function(event) {
          console.log(String(event.target));
        })
        .on('complete', function() {
          console.log('------------------------');
          console.log('Fastest is ' + this.filter('fastest').pluck('name'));
        })
        .run();
      console.log('========================');
    }
  });
}

function start() {
  var re = process.argv[2] ? new RegExp(process.argv[2], 'i') : /./;

  benchmarks.filter(function(b) {
    return re.test(b.name);
  }).forEach(function(b) {
    b.start();
  });
}

var str = 'big benchmark against elliptic';

var m1 = hash.sha256().update(str).digest();
var c1 = elliptic.ec(elliptic.curves.secp256k1);
var k1 = c1.genKeyPair();
var s1 = c1.sign(m1, k1);
assert(c1.verify(m1, s1, k1));

var m2 = eccjs.sjcl.hash.sha256.hash('big benchmark against elliptic');
var c2 = eccjs.sjcl.ecc.curves.k256;
var k2 = eccjs.sjcl.ecc.ecdsa.generateKeys(c2, 0);
var s2 = k2.sec.sign(m2, 0);
assert(k2.pub.verify(m2, s2));

add('sign', {
  elliptic: function() {
    c1.sign(m1, k1);
  },
  sjcl: function() {
    k2.sec.sign(m2, 0);
  }
});

add('verify', {
  elliptic: function() {
    c1.verify(m1, s1, k1);
  },
  sjcl: function() {
    k2.pub.verify(m2, s2);
  }
});

add('gen', {
  elliptic: function() {
    c1.genKeyPair().getPublic();
  },
  sjcl: function() {
    eccjs.sjcl.ecc.ecdsa.generateKeys(c2, 0);
  },
});

add('ecdh', {
  elliptic: function() {
    c1.genKeyPair().derive(k1.getPublic());
  }
});

var c1dh = elliptic.ec('curve25519');
var k1dh = c1dh.genKeyPair();

var c1ed = elliptic.ec('ed25519');
var k1ed = c1ed.genKeyPair();
var s1ed = c1ed.sign(m1, k1ed);
assert(c1ed.verify(m1, s1ed, k1ed));

var kp2ed = jodid.eddsa.genKeySeed();
var ku2ed = jodid.eddsa.publicKey(kp2ed);
var s2ed = jodid.eddsa.signature(m1, kp2ed, ku2ed);
assert(jodid.eddsa.checkSig(s2ed, m1, ku2ed));

add('curve25519 gen', {
  elliptic: function() {
    c1dh.genKeyPair().getPublic();
  },
  jodid: function() {
    var p = jodid.eddsa.genKeySeed();
    jodid.dh.publicKey(p);
  }
});

add('curve25519 dh', {
  elliptic: function() {
      k1dh.derive(c1dh.genKeyPair().getPublic());
  },
  jodid: function() {
    var p = jodid.eddsa.genKeySeed();
    jodid.dh.computeKey(kp2ed, jodid.dh.publicKey(p));
  }
});

add('ed25519 sign', {
  elliptic: function() {
    c1ed.sign(m1, k1ed);
  },
  jodid: function() {
    jodid.eddsa.signature(m1, kp2ed, ku2ed);
  }
});

add('ed25519 verify', {
  elliptic: function() {
    c1ed.verify(m1, s1ed, k1ed);
  },
  jodid: function() {
    jodid.eddsa.checkSig(s2ed, m1, ku2ed);
  }
});

start();
