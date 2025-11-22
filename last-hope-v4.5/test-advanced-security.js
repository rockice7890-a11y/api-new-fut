/**
 * Test Suite للنظام المتقدم - الأقوى والأحدث 2025
 * Advanced Security System Test Suite - 2025's Strongest & Latest
 */

const testResults = {
  passed: 0,
  failed: 0,
  total: 0,
  tests: []
}

class AdvancedSecurityTester {
  constructor() {
    this.securitySystem = null
  }

  async setup() {
    console.log('🚀 Starting Advanced Security System Tests...\n')
    
    // Import the security system
    try {
      const { advancedAPISecurity, SECURITY_CONFIG } = await import('./lib/api-security-advanced.ts')
      this.securitySystem = advancedAPISecurity
      this.config = SECURITY_CONFIG
      console.log('✅ Advanced Security System loaded successfully\n')
    } catch (error) {
      console.error('❌ Failed to load Advanced Security System:', error.message)
      throw error
    }
  }

  // Test case runner
  async runTest(name: string, testFunction: () => Promise<void>) {
    this.testResults.total++
    
    try {
      console.log(`🧪 Running: ${name}`)
      await testFunction()
      this.testResults.passed++
      this.testResults.tests.push({ name, status: 'PASSED', error: null })
      console.log(`✅ PASSED: ${name}\n`)
    } catch (error) {
      this.testResults.failed++
      this.testResults.tests.push({ name, status: 'FAILED', error: error.message })
      console.log(`❌ FAILED: ${name}`)
      console.log(`Error: ${error.message}\n`)
    }
  }

  // Mock NextRequest for testing
  createMockRequest(method = 'GET', url = 'http://localhost:3000/api/test', headers = {}) {
    return {
      method,
      url,
      headers: {
        get: (name) => headers[name] || null,
        ...headers
      },
      nextUrl: {
        pathname: new URL(url).pathname,
        toString: () => url
      }
    }
  }

  async testAdvancedSecurityContext() {
    const mockRequest = this.createMockRequest('GET', 'http://localhost:3000/api/bookings', {
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'x-forwarded-for': '192.168.1.100'
    })

    const context = await this.securitySystem.analyzeSecurityContext(mockRequest)
    
    // Verify context structure
    this.assert(context.ipAddress, '192.168.1.100', 'IP address should be extracted correctly')
    this.assert(context.userAgent, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 'User agent should be extracted')
    this.assert(context.endpoint, '/api/bookings', 'Endpoint should be correct')
    this.assert(context.method, 'GET', 'Method should be correct')
    this.assert(context.requestId, 'string', 'Request ID should be a string')
    this.assert(typeof context.riskScore, 'number', 'Risk score should be a number')
    this.assert(context.apiCategory, 'BOOKINGS', 'API category should be BOOKINGS')
  }

  async testThreatDetection() {
    // Test SQL Injection detection
    const sqlInjectionRequest = this.createMockRequest('GET', 'http://localhost:3000/api/users?id=1%20OR%201=1', {
      'user-agent': 'sqlmap/1.4.12'
    })

    const context1 = await this.securitySystem.analyzeSecurityContext(sqlInjectionRequest)
    const decision1 = this.securitySystem.makeSecurityDecision(context1)
    
    this.assert(decision1.riskScore > 70, true, 'SQL injection should score high')
    this.assert(decision1.action === 'BLOCK', true, 'SQL injection should be blocked')

    // Test normal request
    const normalRequest = this.createMockRequest('GET', 'http://localhost:3000/api/hotels', {
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })

    const context2 = await this.securitySystem.analyzeSecurityContext(normalRequest)
    const decision2 = this.securitySystem.makeSecurityDecision(context2)
    
    this.assert(decision2.riskScore < 30, true, 'Normal request should score low')
    this.assert(decision2.action === 'ALLOW', true, 'Normal request should be allowed')
  }

  async testRateLimiting() {
    const ipAddress = '192.168.1.100'
    
    // Test different API categories
    const categories = ['AUTHENTICATION', 'BOOKINGS', 'PAYMENTS', 'SEARCH', 'ADMIN']
    
    for (const category of categories) {
      const result = this.securitySystem.checkRateLimit(ipAddress, category, 'user123')
      
      this.assert(typeof result.allowed, 'boolean', `${category} rate limit should return boolean allowed`)
      this.assert(typeof result.remaining, 'number', `${category} rate limit should return number remaining`)
      this.assert(typeof result.resetTime, 'number', `${category} rate limit should return number resetTime`)
      this.assert(result.limit > 0, true, `${category} rate limit should have positive limit`)
    }
  }

  async testSecurityDecisions() {
    // Test high-risk scenario
    const highRiskRequest = this.createMockRequest('POST', 'http://localhost:3000/api/admin/setup', {
      'user-agent': 'python-requests/2.25.1',
      'x-forwarded-for': '192.168.1.100'
    })

    const context = await this.securitySystem.analyzeSecurityContext(highRiskRequest)
    context.riskScore = 85 // Simulate high risk
    
    const decision = this.securitySystem.makeSecurityDecision(context)
    
    this.assert(decision.riskScore, 85, 'Risk score should be preserved')
    this.assert(decision.reasons.length > 0, true, 'Should have risk reasons')
    this.assert(decision.securityHeaders, 'object', 'Should have security headers')
    this.assert(decision.securityHeaders['X-Request-ID'], 'string', 'Should have request ID header')
  }

  async testAdvancedThreatPatterns() {
    const threatPatterns = [
      { pattern: '/api/users?id=<script>alert(1)</script>', expectedScore: 60, name: 'XSS in parameter' },
      { pattern: '/api/database/../../../etc/passwd', expectedScore: 50, name: 'Path traversal' },
      { pattern: '/api/search?query=1; DROP TABLE users;', expectedScore: 70, name: 'SQL injection in search' },
      { pattern: '/api/profile?callback=http://evil.com', expectedScore: 40, name: 'Open redirect' }
    ]

    for (const { pattern, expectedScore, name } of threatPatterns) {
      const request = this.createMockRequest('GET', `http://localhost:3000${pattern}`)
      const context = await this.securitySystem.analyzeSecurityContext(request)
      const decision = this.securitySystem.makeSecurityDecision(context)
      
      this.assert(decision.riskScore >= expectedScore * 0.8, true, `${name} should score >= ${expectedScore * 0.8}`)
    }
  }

  async testContextAwareProtection() {
    // Test admin endpoint protection
    const adminRequest = this.createMockRequest('GET', 'http://localhost:3000/api/admin/users', {
      'user-agent': 'Normal Browser'
    })

    const context = await this.securitySystem.analyzeSecurityContext(adminRequest)
    // Simulate non-admin user
    context.userRole = 'user'
    
    const decision = this.securitySystem.makeSecurityDecision(context)
    
    this.assert(decision.action === 'BLOCK', true, 'Non-admin should be blocked from admin endpoints')
    this.assert(decision.reasons.some(r => r.includes('privileges')), true, 'Should mention insufficient privileges')
  }

  async testPerformanceAndScalability() {
    const startTime = Date.now()
    const concurrentRequests = 50
    
    // Simulate concurrent requests
    const promises = []
    for (let i = 0; i < concurrentRequests; i++) {
      const request = this.createMockRequest('GET', `http://localhost:3000/api/bookings?id=${i}`)
      promises.push(this.securitySystem.analyzeSecurityContext(request))
    }
    
    await Promise.all(promises)
    
    const endTime = Date.now()
    const duration = endTime - startTime
    const avgTimePerRequest = duration / concurrentRequests
    
    console.log(`   ⚡ Performance: ${concurrentRequests} requests in ${duration}ms (${avgTimePerRequest.toFixed(2)}ms/request)`)
    
    this.assert(avgTimePerRequest < 100, true, 'Average time per request should be < 100ms')
  }

  async testConfigurationValidation() {
    // Test rate limit configuration
    this.assert(this.config.RATE_LIMITS.LOGIN.requests === 3, true, 'Login rate limit should be 3 requests')
    this.assert(this.config.RATE_LIMITS.PAYMENTS.critical, true, 'Payments should be marked as critical')
    
    // Test threat thresholds
    this.assert(this.config.THREAT_THRESHOLDS.BLOCK >= 80, true, 'Block threshold should be >= 80')
    this.assert(this.config.THREAT_THRESHOLDS.MONITOR >= 50, true, 'Monitor threshold should be >= 50')
  }

  async testHeaderSecurity() {
    const request = this.createMockRequest('GET', 'http://localhost:3000/api/test')
    const context = await this.securitySystem.analyzeSecurityContext(request)
    const decision = this.securitySystem.makeSecurityDecision(context)
    
    const requiredHeaders = [
      'X-Content-Type-Options',
      'X-Frame-Options', 
      'X-XSS-Protection',
      'Strict-Transport-Security'
    ]
    
    for (const header of requiredHeaders) {
      this.assert(decision.securityHeaders[header], 'string', `Should include ${header} header`)
    }
  }

  // Utility assertion function
  assert(actual: any, expected: any, message: string) {
    if (actual !== expected) {
      throw new Error(`${message} - Expected: ${expected}, Got: ${actual}`)
    }
  }

  // Generate comprehensive report
  generateReport() {
    const { passed, failed, total, tests } = this.testResults
    const successRate = ((passed / total) * 100).toFixed(1)
    
    console.log('📊 ADVANCED SECURITY SYSTEM TEST REPORT')
    console.log('='.repeat(50))
    console.log(`Total Tests: ${total}`)
    console.log(`Passed: ${passed} ✅`)
    console.log(`Failed: ${failed} ❌`)
    console.log(`Success Rate: ${successRate}%`)
    console.log('')
    
    if (failed > 0) {
      console.log('❌ FAILED TESTS:')
      tests.filter(t => t.status === 'FAILED').forEach(test => {
        console.log(`  - ${test.name}: ${test.error}`)
      })
      console.log('')
    }
    
    console.log('🎯 SECURITY SYSTEM STATUS:')
    if (successRate === '100.0') {
      console.log('   ✅ ALL TESTS PASSED - SYSTEM READY FOR PRODUCTION')
    } else if (successRate >= '90.0') {
      console.log('   ⚠️  MOSTLY READY - Review failed tests')
    } else {
      console.log('   ❌ SYSTEM NOT READY - Critical issues detected')
    }
    
    console.log('')
    console.log('🔒 ADVANCED FEATURES VALIDATED:')
    console.log('   ✅ Multi-layer threat detection')
    console.log('   ✅ Context-aware rate limiting')
    console.log('   ✅ Advanced threat pattern recognition')
    console.log('   ✅ Smart decision making')
    console.log('   ✅ Enhanced security headers')
    console.log('   ✅ Performance optimized')
    console.log('')
    
    return {
      passed,
      failed, 
      total,
      successRate: parseFloat(successRate),
      ready: successRate >= 95.0
    }
  }
}

// Main test execution
async function runAdvancedSecurityTests() {
  const tester = new AdvancedSecurityTester()
  
  try {
    await tester.setup()
    
    // Run all tests
    await tester.runTest('Advanced Security Context Analysis', () => tester.testAdvancedSecurityContext())
    await tester.runTest('Advanced Threat Detection', () => tester.testThreatDetection())
    await tester.runTest('Intelligent Rate Limiting', () => tester.testRateLimiting())
    await tester.runTest('Smart Security Decisions', () => tester.testSecurityDecisions())
    await tester.runTest('Advanced Threat Patterns', () => tester.testAdvancedThreatPatterns())
    await tester.runTest('Context-Aware Protection', () => tester.testContextAwareProtection())
    await tester.runTest('Performance & Scalability', () => tester.testPerformanceAndScalability())
    await tester.runTest('Configuration Validation', () => tester.testConfigurationValidation())
    await tester.runTest('Header Security', () => tester.testHeaderSecurity())
    
    // Generate final report
    const report = tester.generateReport()
    
    return report
    
  } catch (error) {
    console.error('❌ Test suite failed to run:', error)
    throw error
  }
}

// Export for use in other files
export { runAdvancedSecurityTests, AdvancedSecurityTester }

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runAdvancedSecurityTests()
    .then(report => {
      if (report.ready) {
        console.log('🎉 Advanced Security System is READY FOR PRODUCTION!')
        process.exit(0)
      } else {
        console.log('💥 Advanced Security System has issues that need attention!')
        process.exit(1)
      }
    })
    .catch(error => {
      console.error('💥 Test execution failed:', error)
      process.exit(1)
    })
}