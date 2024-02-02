const Web3 = require('web3');

// Connect to the Ethereum node (Sepolia Testnet)
const web3 = new Web3('https://sepolia.infura.io/v3/af91f7d6b2d6491299b2920958fcd06d');

// Replace the following with your actual values
const fromAddress = '0x47Ea71715F8049B80eD5C20d105e9C5D7631113f';
const toAddress = '0x6B61fd05FA7e73c2de6B1999A390Fee252109072';
const valueInEther = 0.1; // Amount in Ether
const gasPriceInGwei = 20;
const gasLimit = 22000;

// Convert value to Wei
const valueInWei = web3.utils.toWei(valueInEther.toString(), 'ether');

// Create transaction object
const transactionObject = {
  from: fromAddress,
  to: toAddress,
  value: valueInWei,
  gasPrice: web3.utils.toWei(gasPriceInGwei.toString(), 'gwei'),
  gas: gasLimit,
};

// Get the transaction data without signing it
const unsignedTransactionHex = web3.eth.accounts.signTransaction(transactionObject, '').rawTransaction;

console.log('Unsigned Transaction Hex:', unsignedTransactionHex);
