const mongoose = require('mongoose');
const config = require('./env');

let inMemoryServer = null;

const connectDB = async () => {
  try {
    // Attempt standard connection to specified MONGODB_URI
    console.log(`📡 Connecting to MongoDB at ${config.MONGODB_URI}...`);
    const conn = await mongoose.connect(config.MONGODB_URI, {
      serverSelectionTimeoutMS: 4000
    });
    console.log(`✅ MongoDB Connected: ${conn.connection.host}/${conn.connection.name}`);
    return conn;
  } catch (error) {
    console.warn(`⚠️ Could not connect to primary MongoDB URI (${error.message}).`);
    console.log('🔄 Attempting fallback to in-memory MongoDB for seamless local/demo execution...');

    try {
      const { MongoMemoryServer } = require('mongodb-memory-server');
      inMemoryServer = await MongoMemoryServer.create();
      const inMemoryUri = inMemoryServer.getUri();
      console.log(`🚀 In-Memory MongoDB Server started at: ${inMemoryUri}`);
      
      const conn = await mongoose.connect(inMemoryUri);
      console.log(`✅ MongoDB Connected to In-Memory Instance! (Data is active for this session)`);
      return conn;
    } catch (fallbackError) {
      console.error('❌ Failed to start in-memory MongoDB fallback:', fallbackError.message);
      console.error('💡 Please make sure MongoDB is running locally or provide a valid MONGODB_URI in your .env file.');
      throw error;
    }
  }
};

const closeDB = async () => {
  await mongoose.connection.close();
  if (inMemoryServer) {
    await inMemoryServer.stop();
  }
};

module.exports = { connectDB, closeDB };
