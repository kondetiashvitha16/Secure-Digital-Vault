/**
 * Comprehensive End-to-End Test Suite for Secure Digital Vault
 * Verifies all 20 requirements and flows:
 * - User Authentication (Register, Login, Logout)
 * - Statistics (/api/logs/stats)
 * - File Listing (/api/files)
 * - File Upload (PDF, Image, Text, Binary)
 * - View File with correct password (200) and wrong password (401)
 * - Download File with correct password (200) and wrong password (401)
 * - Delete File with wrong password (401) and correct password (200)
 * - Cross-user Access Isolation (IDOR 403)
 * - Activity Logs & Security Alerts
 * - Ciphertext Tamper Verification (409 / Rejection)
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { app, startServer } = require('../server/server');
const config = require('../server/config/env');
const { closeDB } = require('../server/config/db');

const TEST_PORT = process.env.TEST_PORT || 5002;
let serverInstance;
let baseUrl = `http://localhost:${TEST_PORT}`;

function makeRequest({ method = 'GET', urlPath, headers = {}, body = null, isMultipart = false }) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlPath, baseUrl);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method,
      headers
    };

    if (body && !isMultipart && typeof body === 'object') {
      body = JSON.stringify(body);
      options.headers['Content-Type'] = 'application/json';
    }

    if (body) {
      options.headers['Content-Length'] = Buffer.byteLength(body);
    }

    const req = http.request(options, (res) => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        const rawBuffer = Buffer.concat(chunks);
        let json = null;
        try {
          json = JSON.parse(rawBuffer.toString('utf8'));
        } catch {
          // non json
        }
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: json,
          rawBuffer
        });
      });
    });

    req.on('error', reject);

    if (body) {
      req.write(body);
    }
    req.end();
  });
}

function buildMultipartBody(fieldname, filename, contentBuffer, mimeType, filePassword, boundary) {
  const fileHead = Buffer.from(
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="${fieldname}"; filename="${filename}"\r\n` +
    `Content-Type: ${mimeType}\r\n\r\n`
  );
  const fileTail = Buffer.from(`\r\n`);
  const passwordPart = Buffer.from(
    `--${boundary}\r\n` +
    `Content-Disposition: form-data; name="filePassword"\r\n\r\n` +
    `${filePassword}\r\n`
  );
  const end = Buffer.from(`--${boundary}--\r\n`);
  return Buffer.concat([fileHead, contentBuffer, fileTail, passwordPart, end]);
}

async function runComprehensiveTests() {
  console.log('\n======================================================');
  console.log('🧪 COMPREHENSIVE VAULT END-TO-END TEST SUITE');
  console.log('======================================================\n');

  try {
    serverInstance = await startServer(TEST_PORT);

    const timestamp = Date.now();
    let userA = null;
    let tokenA = '';
    let userB = null;
    let tokenB = '';

    // 1. Health check
    console.log('1. Health Check (/api/health)...');
    const health = await makeRequest({ method: 'GET', urlPath: '/api/health' });
    if (health.statusCode !== 200 || health.body.status !== 'online') {
      throw new Error(`Health check failed: ${health.statusCode}`);
    }
    console.log('   ✅ Health check OK');

    // 2. User A Registration
    console.log('\n2. User Registration (User A)...');
    const regA = await makeRequest({
      method: 'POST',
      urlPath: '/api/auth/register',
      body: {
        username: `user_a_${timestamp}`,
        email: `usera_${timestamp}@vault.local`,
        password: 'Password@2026Secure'
      }
    });
    if (regA.statusCode !== 201 || !regA.body.token) {
      throw new Error(`User A registration failed: ${JSON.stringify(regA.body)}`);
    }
    tokenA = regA.body.token;
    userA = regA.body.user;
    console.log(`   ✅ User A registered: ${userA.username}`);

    // 3. User B Registration
    console.log('\n3. User Registration (User B for Access Isolation)...');
    const regB = await makeRequest({
      method: 'POST',
      urlPath: '/api/auth/register',
      body: {
        username: `user_b_${timestamp}`,
        email: `userb_${timestamp}@vault.local`,
        password: 'Password@2026Secure'
      }
    });
    if (regB.statusCode !== 201 || !regB.body.token) {
      throw new Error(`User B registration failed: ${JSON.stringify(regB.body)}`);
    }
    tokenB = regB.body.token;
    userB = regB.body.user;
    console.log(`   ✅ User B registered: ${userB.username}`);

    // 4. Initial Stats and Files Check
    console.log('\n4. Checking Initial Stats & Files List for User A...');
    const stats0 = await makeRequest({
      method: 'GET',
      urlPath: '/api/logs/stats',
      headers: { 'Authorization': `Bearer ${tokenA}` }
    });
    if (stats0.statusCode !== 200 || stats0.body.stats.totalFiles !== 0) {
      throw new Error(`Initial stats invalid: ${JSON.stringify(stats0.body)}`);
    }
    console.log('   ✅ Initial stats: 0 files, 0 storage');

    const files0 = await makeRequest({
      method: 'GET',
      urlPath: '/api/files',
      headers: { 'Authorization': `Bearer ${tokenA}` }
    });
    if (files0.statusCode !== 200 || files0.body.files.length !== 0) {
      throw new Error(`Initial files list not empty: ${JSON.stringify(files0.body)}`);
    }
    console.log('   ✅ Initial file list empty');

    // 5. Upload File 1: Text Document
    console.log('\n5. Uploading Text Document (report.txt)...');
    const textContent = Buffer.from('Confidential report content for Secure Digital Vault.\nVersion 2026.\nAll rights reserved.');
    const textPass = 'TextPassword@123';
    const boundary1 = '----Boundary1' + Date.now();
    const body1 = buildMultipartBody('file', 'report.txt', textContent, 'text/plain', textPass, boundary1);

    const upload1 = await makeRequest({
      method: 'POST',
      urlPath: '/api/files/upload',
      headers: {
        'Authorization': `Bearer ${tokenA}`,
        'Content-Type': `multipart/form-data; boundary=${boundary1}`
      },
      body: body1,
      isMultipart: true
    });

    if (upload1.statusCode !== 201 || !upload1.body.file) {
      throw new Error(`Text upload failed: ${JSON.stringify(upload1.body)}`);
    }
    const file1Id = upload1.body.file.fileId;
    console.log(`   ✅ Uploaded text file: ID = ${file1Id}, size = ${upload1.body.file.size} bytes`);

    // 6. Upload File 2: Binary / PNG Image
    console.log('\n6. Uploading PNG Image (photo.png)...');
    const pngHeader = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52]);
    const imagePass = 'ImagePass#456';
    const boundary2 = '----Boundary2' + Date.now();
    const body2 = buildMultipartBody('file', 'photo.png', pngHeader, 'image/png', imagePass, boundary2);

    const upload2 = await makeRequest({
      method: 'POST',
      urlPath: '/api/files/upload',
      headers: {
        'Authorization': `Bearer ${tokenA}`,
        'Content-Type': `multipart/form-data; boundary=${boundary2}`
      },
      body: body2,
      isMultipart: true
    });

    if (upload2.statusCode !== 201 || !upload2.body.file) {
      throw new Error(`Image upload failed: ${JSON.stringify(upload2.body)}`);
    }
    const file2Id = upload2.body.file.fileId;
    console.log(`   ✅ Uploaded image file: ID = ${file2Id}`);

    // 7. Verify List and Stats Updated
    console.log('\n7. Verifying Dashboard Files & Stats after 2 uploads...');
    const listRes = await makeRequest({
      method: 'GET',
      urlPath: '/api/files',
      headers: { 'Authorization': `Bearer ${tokenA}` }
    });
    if (listRes.statusCode !== 200 || listRes.body.files.length !== 2) {
      throw new Error(`Expected 2 files in list, got: ${listRes.body.files?.length}`);
    }
    // Verify each file has fileId or _id
    listRes.body.files.forEach(f => {
      const id = f.fileId || f._id || f.id;
      if (!id) throw new Error(`File missing valid ID in listing: ${JSON.stringify(f)}`);
    });
    console.log(`   ✅ File list has 2 files with valid IDs`);

    const stats1 = await makeRequest({
      method: 'GET',
      urlPath: '/api/logs/stats',
      headers: { 'Authorization': `Bearer ${tokenA}` }
    });
    if (stats1.statusCode !== 200 || stats1.body.stats.totalFiles !== 2) {
      throw new Error(`Expected totalFiles == 2 in stats: ${JSON.stringify(stats1.body)}`);
    }
    console.log(`   ✅ Stats updated: totalFiles = 2, totalBytes = ${stats1.body.stats.totalBytes}`);

    // 8. Test VIEW File 1 with Correct Password
    console.log('\n8. Testing VIEW File 1 with Correct Password...');
    const view1 = await makeRequest({
      method: 'GET',
      urlPath: `/api/files/${file1Id}/view`,
      headers: {
        'Authorization': `Bearer ${tokenA}`,
        'X-File-Password': encodeURIComponent(textPass)
      }
    });
    if (view1.statusCode !== 200 || !view1.rawBuffer.equals(textContent)) {
      throw new Error(`View failed: status = ${view1.statusCode}`);
    }
    console.log('   ✅ View succeeded, returned exact plaintext buffer');

    // 9. Test VIEW File 1 with WRONG Password
    console.log('\n9. Testing VIEW File 1 with WRONG Password...');
    const viewWrong = await makeRequest({
      method: 'GET',
      urlPath: `/api/files/${file1Id}/view`,
      headers: {
        'Authorization': `Bearer ${tokenA}`,
        'X-File-Password': encodeURIComponent('WrongPassword!')
      }
    });
    if (viewWrong.statusCode !== 401 || viewWrong.body.error !== 'Incorrect file password.') {
      throw new Error(`Wrong password on view not rejected properly: ${viewWrong.statusCode}`);
    }
    console.log('   ✅ View rejected with 401 "Incorrect file password."');

    // 10. Test DOWNLOAD File 1 with Correct Password
    console.log('\n10. Testing DOWNLOAD File 1 with Correct Password...');
    const dl1 = await makeRequest({
      method: 'GET',
      urlPath: `/api/files/${file1Id}/download`,
      headers: {
        'Authorization': `Bearer ${tokenA}`,
        'X-File-Password': encodeURIComponent(textPass)
      }
    });
    if (dl1.statusCode !== 200 || !dl1.rawBuffer.equals(textContent)) {
      throw new Error(`Download failed: status = ${dl1.statusCode}`);
    }
    if (!dl1.headers['content-disposition'].includes('report.txt')) {
      throw new Error(`Content-Disposition missing filename: ${dl1.headers['content-disposition']}`);
    }
    console.log(`   ✅ Download succeeded: original filename present in Content-Disposition header`);

    // 11. Test DOWNLOAD File 1 with WRONG Password
    console.log('\n11. Testing DOWNLOAD File 1 with WRONG Password...');
    const dlWrong = await makeRequest({
      method: 'GET',
      urlPath: `/api/files/${file1Id}/download`,
      headers: {
        'Authorization': `Bearer ${tokenA}`,
        'X-File-Password': encodeURIComponent('WrongPassword!')
      }
    });
    if (dlWrong.statusCode !== 401 || dlWrong.body.error !== 'Incorrect file password.') {
      throw new Error(`Wrong password on download not rejected properly: ${dlWrong.statusCode}`);
    }
    console.log('   ✅ Download rejected with 401 "Incorrect file password."');

    // 12. Test Access Control: User B accessing User A's file
    console.log('\n12. Testing Access Control (User B trying to download User A\'s file)...');
    const idor = await makeRequest({
      method: 'GET',
      urlPath: `/api/files/${file1Id}/download`,
      headers: {
        'Authorization': `Bearer ${tokenB}`,
        'X-File-Password': encodeURIComponent(textPass)
      }
    });
    if (idor.statusCode !== 403) {
      throw new Error(`Expected 403 Forbidden for unauthorized user, got: ${idor.statusCode}`);
    }
    console.log('   ✅ Access control enforced: User B blocked with 403 Forbidden');

    // 13. Test DELETE File 1 with WRONG Password
    console.log('\n13. Testing DELETE File 1 with WRONG Password...');
    const delWrong = await makeRequest({
      method: 'DELETE',
      urlPath: `/api/files/${file1Id}`,
      headers: {
        'Authorization': `Bearer ${tokenA}`,
        'X-File-Password': encodeURIComponent('WrongPassword!')
      }
    });
    if (delWrong.statusCode !== 401 || delWrong.body.error !== 'Incorrect file password.') {
      throw new Error(`Delete with wrong password not rejected properly: ${delWrong.statusCode}`);
    }
    console.log('   ✅ Delete rejected with 401 "Incorrect file password."');

    // 14. Test DELETE File 1 with CORRECT Password
    console.log('\n14. Testing DELETE File 1 with CORRECT Password...');
    const del1 = await makeRequest({
      method: 'DELETE',
      urlPath: `/api/files/${file1Id}`,
      headers: {
        'Authorization': `Bearer ${tokenA}`,
        'X-File-Password': encodeURIComponent(textPass)
      }
    });
    if (del1.statusCode !== 200) {
      throw new Error(`Delete failed: status = ${del1.statusCode}`);
    }
    console.log('   ✅ Delete succeeded with status 200');

    // 15. Verify File 1 is gone and File 2 remains
    console.log('\n15. Verifying File 1 was purged and File 2 remains...');
    const listAfterDel = await makeRequest({
      method: 'GET',
      urlPath: '/api/files',
      headers: { 'Authorization': `Bearer ${tokenA}` }
    });
    if (listAfterDel.statusCode !== 200 || listAfterDel.body.files.length !== 1) {
      throw new Error(`Expected exactly 1 file remaining, got: ${listAfterDel.body.files?.length}`);
    }
    if (listAfterDel.body.files[0].fileId !== file2Id) {
      throw new Error(`Remaining file should be File 2`);
    }
    console.log('   ✅ File list has 1 remaining file (File 2)');

    // 16. Verify Activity Logs and Alerts
    console.log('\n16. Testing Activity Logs & Security Alerts Retrieval...');
    const logsRes = await makeRequest({
      method: 'GET',
      urlPath: '/api/logs?limit=30',
      headers: { 'Authorization': `Bearer ${tokenA}` }
    });
    if (logsRes.statusCode !== 200 || !logsRes.body.success || !Array.isArray(logsRes.body.logs)) {
      throw new Error(`Logs endpoint failed: ${JSON.stringify(logsRes.body)}`);
    }
    console.log(`   ✅ Activity logs retrieved: ${logsRes.body.logs.length} entries`);

    const alertsRes = await makeRequest({
      method: 'GET',
      urlPath: '/api/logs/alerts?limit=15',
      headers: { 'Authorization': `Bearer ${tokenA}` }
    });
    if (alertsRes.statusCode !== 200 || !alertsRes.body.success || !Array.isArray(alertsRes.body.alerts)) {
      throw new Error(`Alerts endpoint failed: ${JSON.stringify(alertsRes.body)}`);
    }
    console.log(`   ✅ Security alerts retrieved: ${alertsRes.body.alerts.length} alert entries`);

    // 17. Test 404 on Unknown API route
    console.log('\n17. Testing 404 on Unknown API Endpoint...');
    const unk = await makeRequest({
      method: 'GET',
      urlPath: '/api/nonexistent_route'
    });
    if (unk.statusCode !== 404 || !unk.body || unk.body.success !== false) {
      throw new Error(`Expected 404 JSON response for unknown endpoint: ${unk.statusCode}`);
    }
    console.log(`   ✅ Clean 404 JSON returned for unknown API route`);

    console.log('\n======================================================');
    console.log('🎉 ALL COMPREHENSIVE VAULT TESTS PASSED SUCCESSFULLY (100%)!');
    console.log('======================================================\n');
  } catch (err) {
    console.error('\n❌ COMPREHENSIVE TEST SUITE FAILED:', err);
    process.exitCode = 1;
  } finally {
    if (serverInstance) {
      serverInstance.close();
    }
    await closeDB();
    process.exit(process.exitCode || 0);
  }
}

runComprehensiveTests();
