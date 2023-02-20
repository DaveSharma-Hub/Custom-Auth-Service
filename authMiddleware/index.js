const crypto = require('crypto');
const jwt = require('@nuclear-packages/jwt-creator');

const algorithm = 'aes-256-cbc'; //Using AES encryption
const iv = crypto.randomBytes(16);


function helperDecrypt(data,encryptionKey){
   const key = crypto.createHash('sha256',encryptionKey).digest('hex').slice(32);;
   let encryptedText = Buffer.from(data.toString(),'hex');
   let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
   let decrypted = decipher.update(encryptedText);
   decrypted = Buffer.concat([decrypted, decipher.final()]);
   return decrypted.toString();
}

/**
 * decrypt all data
 */

function decryptData(data,encryptionKey){
    // assuming json/object format data
    const dataArray = [...data];
    dataArray.map((dataObject,index)=>{
        Object.entries(dataObject).map((keyValuePair)=>{
            const key = keyValuePair[0];
            const value = keyValuePair[1];
            dataArray[index][key] = helperDecrypt(value,encryptionKey);
        })
    })
    return dataArray;
}


function helperEncrypt(data,encryptionKey){
    const key = crypto.createHash('sha256',encryptionKey).digest('hex').slice(32);
    let cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
    let encrypted = cipher.update(data.toString());
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return encrypted.toString('hex')
}
/**
 * encrypt all data sending in json format
 */

function encryptData(data,encryptionKey){
    const dataArray = [...data];
    dataArray.map((dataObject,index)=>{
        Object.entries(dataObject).map((keyValuePair)=>{
            const key = keyValuePair[0];
            const value = keyValuePair[1];
            dataArray[index][key] = helperEncrypt(value,encryptionKey);
        })
    })
    return dataArray;
}

/*
    includes both jwt and ttl token that expires
*/
function webTokenCreator(payload,password){
    const password_secret = crypto.createHash('sha256',password).digest('hex');
    return jwt.createJWTSHA256(payload,password_secret);
}


/*
    validates the web token
*/
function webTokenValidator(jwtToken,password){
    const password_secret = crypto.createHash('sha256',password).digest('hex');
    return jwt.verifyJWTSHA256(jwtToken,password_secret);
}

/*
    Authorize data based on the permission set and action set
*/
function dataAuthorizor(jwtToken, password,userPermission, actionSet){
    if(webTokenValidator(jwtToken,password)){
        const action = actionSet[userPermission];
        if(typeof action === 'function'){
            return action;
        }else{
            console.log('Error in action step');
            return ()=>{console.log('Error')}
        }
    }else{
        console.log('Error in jwt validating step');
        return ()=>{console.log('Incorrect JWT')}
    }
}

module.exports = {
    decryptData:decryptData,
    encryptData:encryptData,
    webTokenCreator:webTokenCreator,
    webTokenValidator:webTokenValidator,
    dataAuthorizor:dataAuthorizor
}