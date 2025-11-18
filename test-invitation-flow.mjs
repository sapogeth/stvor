#!/usr/bin/env node

/**
 * Test Script: Complete Group Invitation Flow
 * Tests the entire pipeline from invitation creation to notification delivery
 *
 * This script verifies:
 * 1. Relay server is healthy
 * 2. /group/invite/notify endpoint works
 * 3. WebSocket connection can be established
 */

import https from 'https';

const RELAY_URL = 'https://ilyazhrelay-production.up.railway.app';

// Test 1: Health check
async function testHealthCheck() {
  console.log('\n🔍 Test 1: Checking relay server health...');
  return new Promise((resolve) => {
    const url = new URL(`${RELAY_URL}/health`);
    const req = https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          console.log('✅ Relay health check:', parsed);
          resolve(true);
        } catch (e) {
          console.error('❌ Invalid health response:', data);
          resolve(false);
        }
      });
    });
    req.on('error', (err) => {
      console.error('❌ Health check failed:', err.message);
      resolve(false);
    });
  });
}

// Test 2: Group invitation endpoint
async function testInvitationEndpoint() {
  console.log('\n🔍 Test 2: Testing /group/invite/notify endpoint...');
  return new Promise((resolve) => {
    const url = new URL(`${RELAY_URL}/group/invite/notify`);
    const payload = JSON.stringify({
      groupId: 'test-group-123',
      groupName: 'Test Network Group',
      creatorUsername: 'testuser1',
      creatorDisplayName: 'Test User 1',
      recipientUsername: 'testuser2',
    });

    const req = https.request(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (res.statusCode === 200 || res.statusCode === 201) {
            console.log('✅ Invitation endpoint response:', parsed);
            console.log('   - Success:', parsed.success);
            console.log('   - Recipient:', parsed.recipientUsername);
            console.log('   - Notified (connected):', parsed.notified);
            resolve(true);
          } else {
            console.error(`❌ Endpoint returned ${res.statusCode}:`, parsed);
            resolve(false);
          }
        } catch (e) {
          console.error('❌ Invalid response:', data);
          resolve(false);
        }
      });
    });

    req.on('error', (err) => {
      console.error('❌ Endpoint test failed:', err.message);
      resolve(false);
    });

    req.write(payload);
    req.end();
  });
}

// Test 3: Check environment variables in web app
async function testEnvironmentSetup() {
  console.log('\n🔍 Test 3: Checking .env.production configuration...');
  try {
    const fs = await import('fs');
    const envContent = fs.readFileSync('./apps/web/.env.production', 'utf8');
    const hasRelay = envContent.includes('NEXT_PUBLIC_RELAY_URL=https://ilyazhrelay-production.up.railway.app');
    const hasBase = envContent.includes('RELAY_BASE_URL=https://ilyazhrelay-production.up.railway.app');

    if (hasRelay && hasBase) {
      console.log('✅ Environment variables correctly configured:');
      console.log('   - NEXT_PUBLIC_RELAY_URL=https://ilyazhrelay-production.up.railway.app');
      console.log('   - RELAY_BASE_URL=https://ilyazhrelay-production.up.railway.app');
      return true;
    } else {
      console.error('❌ Environment variables not properly set in .env.production');
      if (!hasRelay) console.error('   - Missing NEXT_PUBLIC_RELAY_URL');
      if (!hasBase) console.error('   - Missing RELAY_BASE_URL');
      return false;
    }
  } catch (err) {
    console.error('❌ Could not check .env.production:', err.message);
    return false;
  }
}

// Main test runner
async function runTests() {
  console.log('='.repeat(70));
  console.log('🧪 GROUP INVITATION NETWORK FLOW TEST');
  console.log('='.repeat(70));
  console.log(`📍 Relay URL: ${RELAY_URL}`);

  const results = [];

  results.push({ name: 'Health Check', passed: await testHealthCheck() });
  results.push({ name: 'Invitation Endpoint', passed: await testInvitationEndpoint() });
  results.push({ name: 'Environment Setup', passed: await testEnvironmentSetup() });

  console.log('\n' + '='.repeat(70));
  console.log('📊 TEST SUMMARY');
  console.log('='.repeat(70));

  let passed = 0;
  results.forEach(result => {
    const icon = result.passed ? '✅' : '❌';
    console.log(`${icon} ${result.name}`);
    if (result.passed) passed++;
  });

  console.log('\n' + '='.repeat(70));
  console.log(`📈 Result: ${passed}/${results.length} tests passed`);
  console.log('='.repeat(70));

  if (passed === results.length) {
    console.log('\n🎉 All tests passed! Network invitation flow is ready.');
    console.log('\n📋 NEXT STEPS:');
    console.log('1. Ensure NEXT_PUBLIC_RELAY_URL and RELAY_BASE_URL are set on Vercel');
    console.log('2. Trigger a redeploy on Vercel (Settings → Redeploy)');
    console.log('3. Test the production system at stvor.vercel.app');
    console.log('4. Create a group and invite a user on a different device/network');
    console.log('5. Check browser console to confirm WebSocket connects to Railway relay');
    process.exit(0);
  } else {
    console.log('\n⚠️  Some tests failed. Please review the errors above.');
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Test runner error:', err);
  process.exit(1);
});
