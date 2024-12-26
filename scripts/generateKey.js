const crypto = require('crypto');

const key = crypto.randomBytes(32);
console.log('Add this to your .env file:');
console.log(`ENCRYPTION_KEY=${key.toString('hex')}`); 