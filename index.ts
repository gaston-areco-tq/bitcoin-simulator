import * as crypto from 'crypto';

// Transfer of funds between two wallets
class Transaction {
  constructor(
    public amount: number,
    public payer: string, // public key
    public payee: string // public key
  ) {}

  // Serialize to help encryption methods
  toString() {
    return JSON.stringify(this);
  }
}

// Individual block on the chain
class Block {

  // En criptografía, un nonce es un número arbitrario que se puede usar una
  //   única vez en una comunicación criptográfica. A menudo es un número aleatorio
  //   o pseudoaleatorio emitido en un protocolo de autenticación para garantizar que
  //   las comunicaciones antiguas no se puedan reutilizar en ataques de playback
  public nonce = Math.round(Math.random() * 999999999);

  constructor(
    public prevHash: string,
    public transaction: Transaction,
    // Time stamp
    public ts = Date.now()
  ) {}

  // Hash of the whole block (to be stored in prevHash attribute)
  get hash() {
    const str = JSON.stringify(this);
    // SHA256 Secure Hash Algorithm (link of 256 bits) one way cryptographic function
    const hash = crypto.createHash('SHA256');
    // Updates the hash content with the given data
    hash.update(str).end();
    // Return de hash value as a hexadecimal string
    return hash.digest('hex');
  }
}


// The blockchain - Linked list of blocks
class Chain {
  // Singleton instance
  public static instance = new Chain();

  chain: Block[];

  constructor() {
    this.chain = [
      // Genesis block - First block - Empty prevHash
      new Block('', new Transaction(100, 'genesis', 'satoshi'))
    ];
  }

  // Most recent block
  get lastBlock() {
    return this.chain[this.chain.length - 1];
  }

  // Proof of work system
  mine(nonce: number) {
    // Attempt to find a number that when added to the nonce will produce a hash
    //   that starts with 0000, we can only do it with brute force
    let solution = 1;
    console.log('⛏️  mining...')

    while(true) {

      // Will user md5 that is like sha256 but is only 128 bits so is faster to compute
      const hash = crypto.createHash('MD5');
      hash.update((nonce + solution).toString()).end();

      const attempt = hash.digest('hex');

      // When we find it we return the solution and send it off to other nodes where it can
      //  be verified and the block can be confirmed on the blockchain
      if(attempt.substr(0,4) === '0000'){
        console.log(`Solved: ${solution}`);
        return solution;
      }

      solution += 1;
    }
  }

  // Add a new block to the chain if valid signature & proof of work is complete
  addBlock(transaction: Transaction, senderPublicKey: string, signature: Buffer) {
    // Naive implementation - No way to know this is a legitimate transaction
    // const newBlock = new Block(this.lastBlock.hash, transaction);
    // this.chain.push(newBlock)

    const verify = crypto.createVerify('SHA256');
    verify.update(transaction.toString());

    const isValid = verify.verify(senderPublicKey, signature);

    if (isValid) {
      const newBlock = new Block(this.lastBlock.hash, transaction);
      this.mine(newBlock.nonce);
      this.chain.push(newBlock);
    }
  }

}

// Wallet gives a user a public/private keypair
class Wallet {
  // public key is for receiving money
  public publicKey: string;
  // private key is for spending money
  public privateKey: string;

  constructor() {
    // RSA - Full encryption algorithm (Encrypt with public - Decrypt with private)
    // We are going to use the keypair to create a digital signature, with signing we don't need to
    //   encrypt the message but instead create a hash of it, we then sign the hash with
    //   the private key, then the message can be verified later with the public key
    //   If anyone tries to change the message it will produce a different hash in which case
    //   the verification will fail, why? To prevent transaction interceptions and data
    //   modification (amount, payer, payee)
    const keypair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    this.privateKey = keypair.privateKey;
    this.publicKey = keypair.publicKey;
  }

  sendMoney(amount: number, payeePublicKey: string) {
    // Specifying amount and the public key of the user being paid
    const transaction = new Transaction(amount, this.publicKey, payeePublicKey);

    // Signing
    const sign = crypto.createSign('SHA256');
    // Using the whole transaction as data for the hash
    sign.update(transaction.toString()).end();


    // One time password - It allows us to verify our identity using the private key
    //   without actually exposing it
    // The signature depends on both of the transaction data and the private key, but it
    //   can be verified as authentic using the public key
    const signature = sign.sign(this.privateKey);

    // Attempt to add the block - it's transfer among all other nodes in real blockchain?
    Chain.instance.addBlock(transaction, this.publicKey, signature);
  }
}

// Example usage

const satoshi = new Wallet();
const bob = new Wallet();
const alice = new Wallet();

satoshi.sendMoney(50, bob.publicKey);
bob.sendMoney(23, alice.publicKey);
alice.sendMoney(5, bob.publicKey);

console.log(Chain.instance)


