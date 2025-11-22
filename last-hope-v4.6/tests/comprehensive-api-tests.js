/**
 * Comprehensive Testing Suite for Hotel Management API
 * 
 * This file contains automated tests for all major API endpoints
 * Run with: npm test
 */

const API_BASE_URL = process.env.TEST_API_URL || 'http://localhost:3000/api'

// Test utilities
class APITester {
  constructor(baseURL) {
    this.baseURL = baseURL
    this.authToken = ''
    this.userId = ''
    this.hotelId = ''
    this.roomId = ''
    this.bookingId = ''
    this.reviewId = ''
    this.paymentId = ''
    // New properties for advanced features
    this.contestId = ''
    this.gameId = ''
    this.gameSessionId = ''
    this.recommendationId = ''
    this.advertisementId = ''
    this.loyaltyPoints = 0
  }

  async makeRequest(method, endpoint, data = null, requireAuth = true) {
    const url = `${this.baseURL}${endpoint}`
    const headers = {
      'Content-Type': 'application/json',
      ...(requireAuth && this.authToken && { 'Authorization': `Bearer ${this.authToken}` })
    }

    const config = {
      method,
      headers,
      ...(data && { body: JSON.stringify(data) })
    }

    try {
      const response = await fetch(url, config)
      const responseData = await response.json()
      
      return {
        status: response.status,
        success: response.ok,
        data: responseData,
        headers: response.headers
      }
    } catch (error) {
      console.error(`Request failed: ${method} ${endpoint}`, error)
      return {
        status: 500,
        success: false,
        data: { message: 'Network error' },
        error
      }
    }
  }

  async authenticate() {
    // Register a test user
    const registerResponse = await this.makeRequest('POST', '/auth/register', {
      email: `testuser${Date.now()}@example.com`,
      password: 'SecureTestPass123!',
      firstName: 'Test',
      lastName: 'User'
    }, false)

    if (registerResponse.success && registerResponse.data.data?.token) {
      this.authToken = registerResponse.data.data.token
      this.userId = registerResponse.data.data.user.id
      return registerResponse
    }

    // If registration fails, try login
    return await this.makeRequest('POST', '/auth/login', {
      email: 'test@example.com',
      password: 'password'
    }, false)
  }

  async createTestHotel() {
    const response = await this.makeRequest('POST', '/hotels', {
      name: 'Test Grand Hotel',
      description: 'A luxurious test hotel',
      address: '123 Test Street',
      city: 'Test City',
      country: 'Test Country',
      phone: '+1234567890',
      email: 'test@hotel.com',
      amenities: ['WiFi', 'Pool', 'Gym'],
      checkInTime: '15:00',
      checkOutTime: '11:00'
    })

    if (response.success && response.data.data?.id) {
      this.hotelId = response.data.data.id
    }
    return response
  }

  async createTestRoom() {
    const response = await this.makeRequest('POST', '/rooms', {
      hotelId: this.hotelId,
      roomType: 'Deluxe Suite',
      roomNumber: '101',
      capacity: 2,
      beds: 1,
      basePrice: 150.0,
      description: 'Test room description',
      amenities: ['WiFi', 'TV', 'Mini Bar']
    })

    if (response.success && response.data.data?.id) {
      this.roomId = response.data.data.id
    }
    return response
  }

  async createTestBooking() {
    const response = await this.makeRequest('POST', '/bookings', {
      hotelId: this.hotelId,
      roomId: this.roomId,
      checkInDate: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      checkOutDate: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString(),
      guests: 2,
      guestName: 'Test Guest',
      guestEmail: 'guest@example.com',
      guestPhone: '+1234567890'
    })

    if (response.success && response.data.data?.id) {
      this.bookingId = response.data.data.id
    }
    return response
  }
}

// Test Suite
class HotelAPITestSuite {
  constructor() {
    this.tester = new APITester(API_BASE_URL)
    this.testResults = []
  }

  async runTest(testName, testFunction) {
    console.log(`\n🧪 Running: ${testName}`)
    try {
      const startTime = Date.now()
      const result = await testFunction()
      const duration = Date.now() - startTime
      
      const testResult = {
        name: testName,
        success: result.success,
        status: result.status,
        duration,
        message: result.data.message || 'Test completed',
        details: result.data
      }

      if (result.success) {
        console.log(`✅ PASSED: ${testName} (${duration}ms)`)
      } else {
        console.log(`❌ FAILED: ${testName} - ${result.data.message} (${duration}ms)`)
      }

      this.testResults.push(testResult)
      return result
    } catch (error) {
      console.error(`💥 ERROR in ${testName}:`, error)
      this.testResults.push({
        name: testName,
        success: false,
        status: 500,
        message: error.message,
        error: error.toString()
      })
      return { success: false, data: { message: error.message } }
    }
  }

  async runAllTests() {
    console.log('🚀 Starting Hotel Management API Test Suite')
    console.log('=============================================')

    // Authentication tests
    await this.runTest('User Registration', async () => {
      return await this.tester.authenticate()
    })

    // User profile tests
    await this.runTest('Get User Profile', async () => {
      return await this.tester.makeRequest('GET', '/users/profile')
    })

    await this.runTest('Update User Profile', async () => {
      return await this.tester.makeRequest('PUT', '/users/profile', {
        firstName: 'Updated',
        lastName: 'User',
        phone: '+1234567891'
      })
    })

    // Hotel management tests
    await this.runTest('Create Hotel', async () => {
      return await this.tester.createTestHotel()
    })

    await this.runTest('Get Hotels', async () => {
      return await this.tester.makeRequest('GET', '/hotels')
    })

    await this.runTest('Get Hotel by ID', async () => {
      if (!this.tester.hotelId) return { success: false, data: { message: 'No hotel ID available' } }
      return await this.tester.makeRequest('GET', `/hotels/${this.tester.hotelId}`)
    })

    await this.runTest('Update Hotel', async () => {
      if (!this.tester.hotelId) return { success: false, data: { message: 'No hotel ID available' } }
      return await this.tester.makeRequest('PUT', `/hotels/${this.tester.hotelId}`, {
        name: 'Updated Test Hotel',
        description: 'Updated test description'
      })
    })

    // Room management tests
    await this.runTest('Create Room', async () => {
      if (!this.tester.hotelId) return { success: false, data: { message: 'No hotel ID available' } }
      return await this.tester.createTestRoom()
    })

    await this.runTest('Get Rooms', async () => {
      if (!this.tester.hotelId) return { success: false, data: { message: 'No hotel ID available' } }
      return await this.tester.makeRequest('GET', `/rooms?hotelId=${this.tester.hotelId}`)
    })

    await this.runTest('Get Room by ID', async () => {
      if (!this.tester.roomId) return { success: false, data: { message: 'No room ID available' } }
      return await this.tester.makeRequest('GET', `/rooms/${this.tester.roomId}`)
    })

    // Booking tests
    await this.runTest('Create Booking', async () => {
      if (!this.tester.hotelId || !this.tester.roomId) {
        return { success: false, data: { message: 'Hotel or room ID not available' } }
      }
      return await this.tester.createTestBooking()
    })

    await this.runTest('Get User Bookings', async () => {
      return await this.tester.makeRequest('GET', '/bookings')
    })

    await this.runTest('Get Booking by ID', async () => {
      if (!this.tester.bookingId) return { success: false, data: { message: 'No booking ID available' } }
      return await this.tester.makeRequest('GET', `/bookings/${this.tester.bookingId}`)
    })

    // Reviews tests
    await this.runTest('Create Review', async () => {
      if (!this.tester.hotelId || !this.tester.bookingId) {
        return { success: false, data: { message: 'Hotel or booking ID not available' } }
      }
      const response = await this.tester.makeRequest('POST', '/reviews', {
        hotelId: this.tester.hotelId,
        bookingId: this.tester.bookingId,
        rating: 5,
        comment: 'Excellent hotel!',
        cleanliness: 5,
        comfort: 5,
        service: 5,
        value: 4
      })

      if (response.success && response.data.data?.id) {
        this.tester.reviewId = response.data.data.id
      }
      return response
    })

    await this.runTest('Get Hotel Reviews', async () => {
      if (!this.tester.hotelId) return { success: false, data: { message: 'No hotel ID available' } }
      return await this.tester.makeRequest('GET', `/reviews?hotelId=${this.tester.hotelId}`)
    })

    // Payments tests
    await this.runTest('Create Payment', async () => {
      if (!this.tester.bookingId) return { success: false, data: { message: 'No booking ID available' } }
      const response = await this.tester.makeRequest('POST', '/payments', {
        bookingId: this.tester.bookingId,
        amount: 600.0,
        currency: 'USD',
        method: 'card',
        stripeId: 'pi_test_1234567890'
      })

      if (response.success && response.data.data?.id) {
        this.tester.paymentId = response.data.data.id
      }
      return response
    })

    await this.runTest('Get Payments', async () => {
      return await this.tester.makeRequest('GET', '/payments')
    })

    // Notifications tests
    await this.runTest('Get Notifications', async () => {
      return await this.tester.makeRequest('GET', '/notifications')
    })

    await this.runTest('Mark All Notifications Read', async () => {
      return await this.tester.makeRequest('PUT', '/notifications', {
        action: 'mark_all_read'
      })
    })

    // Upload tests
    await this.runTest('File Upload', async () => {
      // Test upload endpoint structure (file upload would need actual file)
      return await this.tester.makeRequest('POST', '/upload', {
        type: 'test',
        entityId: this.tester.hotelId
      })
    })

    // Search tests
    await this.runTest('Search Hotels', async () => {
      return await this.tester.makeRequest('GET', '/search/hotels?query=hotel&location=Test', false)
    })

    // Wishlist tests
    await this.runTest('Add to Wishlist', async () => {
      if (!this.tester.hotelId) return { success: false, data: { message: 'No hotel ID available' } }
      return await this.tester.makeRequest('POST', '/wishlist', {
        hotelId: this.tester.hotelId
      })
    })

    await this.runTest('Get Wishlist', async () => {
      return await this.tester.makeRequest('GET', '/wishlist')
    })

    // Analytics tests
    await this.runTest('Get User Analytics', async () => {
      return await this.tester.makeRequest('GET', '/analytics/user')
    })

    if (this.tester.hotelId) {
      await this.runTest('Get Hotel Analytics', async () => {
        return await this.tester.makeRequest('GET', `/analytics/hotel?hotelId=${this.tester.hotelId}`)
      })
    }

    // SERVICES TESTING (for room_services_screen.dart)
    await this.runTest('Get Hotel Services', async () => {
      if (!this.tester.hotelId) return { success: false, data: { message: 'No hotel ID available' } }
      return await this.tester.makeRequest('GET', `/services?hotelId=${this.tester.hotelId}`)
    })

    await this.runTest('Get Service Categories', async () => {
      return await this.tester.makeRequest('GET', '/services/categories')
    })

    await this.runTest('Get Service by ID', async () => {
      // First create a service, then get it
      const createResponse = await this.tester.makeRequest('POST', '/services', {
        hotelId: this.tester.hotelId,
        name: 'خدمة تنظيف الغرف',
        description: 'خدمة تنظيف شاملة للغرف',
        category: 'housekeeping',
        price: 50.0,
        duration: 60, // minutes
        isAvailable: true
      })
      
      if (createResponse.success && createResponse.data.data?.id) {
        const serviceId = createResponse.data.data.id
        return await this.tester.makeRequest('GET', `/services/${serviceId}`)
      }
      
      return { success: false, data: { message: 'Failed to create service for testing' } }
    })

    // BOOKING SERVICES TESTING (for room_services_screen.dart)
    await this.runTest('Add Service to Booking', async () => {
      if (!this.tester.bookingId) return { success: false, data: { message: 'No booking ID available' } }
      
      const createServiceResponse = await this.tester.makeRequest('POST', '/services', {
        hotelId: this.tester.hotelId,
        name: 'خدمة إفطار',
        description: 'إفطار شهي في الغرفة',
        category: 'food',
        price: 25.0,
        duration: 15,
        isAvailable: true
      })
      
      if (!createServiceResponse.success) {
        return { success: false, data: { message: 'Failed to create service' } }
      }
      
      const serviceId = createServiceResponse.data.data.id
      return await this.tester.makeRequest('POST', '/booking-services', {
        bookingId: this.tester.bookingId,
        serviceId: serviceId,
        quantity: 2,
        requestedTime: new Date(Date.now() + 2*60*60*1000).toISOString(),
        specialRequests: 'بدون مكسرات'
      })
    })

    await this.runTest('Get Booking Services', async () => {
      if (!this.tester.bookingId) return { success: false, data: { message: 'No booking ID available' } }
      return await this.tester.makeRequest('GET', `/booking-services?bookingId=${this.tester.bookingId}`)
    })

    await this.runTest('Update Booking Service Status', async () => {
      if (!this.tester.bookingId) return { success: false, data: { message: 'No booking ID available' } }
      
      const bookingServicesResponse = await this.tester.makeRequest('GET', `/booking-services?bookingId=${this.tester.bookingId}`)
      if (!bookingServicesResponse.success || !bookingServicesResponse.data.data?.length) {
        return { success: false, data: { message: 'No booking services found' } }
      }
      
      const bookingServiceId = bookingServicesResponse.data.data[0].id
      return await this.tester.makeRequest('PUT', `/booking-services/${bookingServiceId}`, {
        status: 'completed',
        completedAt: new Date().toISOString()
      })
    })

    // BILLING & CALCULATION TESTING (for bill_calculation_screen.dart)
    await this.runTest('Calculate Booking Bill', async () => {
      if (!this.tester.bookingId) return { success: false, data: { message: 'No booking ID available' } }
      return await this.tester.makeRequest('GET', `/billing/calculate/${this.tester.bookingId}`)
    })

    await this.runTest('Get Detailed Bill Breakdown', async () => {
      if (!this.tester.bookingId) return { success: false, data: { message: 'No booking ID available' } }
      return await this.tester.makeRequest('GET', `/billing/breakdown/${this.tester.bookingId}`)
    })

    await this.runTest('Apply Discount to Bill', async () => {
      if (!this.tester.bookingId) return { success: false, data: { message: 'No booking ID available' } }
      return await this.tester.makeRequest('POST', `/billing/discount`, {
        bookingId: this.tester.bookingId,
        discountType: 'LOYALTY',
        discountValue: 10,
        reason: 'Points redemption'
      })
    })

    await this.runTest('Generate Final Invoice', async () => {
      if (!this.tester.bookingId) return { success: false, data: { message: 'No booking ID available' } }
      return await this.tester.makeRequest('POST', '/billing/invoice', {
        bookingId: this.tester.bookingId,
        includeServices: true,
        includeTaxes: true,
        format: 'pdf'
      })
    })

    // STAFF BOOKING MANAGEMENT TESTING (for staff_booking_confirmation_screen.dart)
    await this.runTest('Get Staff Dashboard Bookings', async () => {
      return await this.tester.makeRequest('GET', '/staff/bookings/dashboard', {
        status: 'pending',
        hotelId: this.tester.hotelId,
        dateFrom: new Date().toISOString(),
        dateTo: new Date(Date.now() + 7*24*60*60*1000).toISOString()
      })
    })

    await this.runTest('Confirm Booking by Staff', async () => {
      if (!this.tester.bookingId) return { success: false, data: { message: 'No booking ID available' } }
      return await this.tester.makeRequest('PUT', `/staff/bookings/${this.tester.bookingId}/confirm`, {
        confirmedBy: this.tester.userId,
        confirmedAt: new Date().toISOString(),
        arrivalTime: new Date(Date.now() + 3*60*60*1000).toISOString(),
        specialInstructions: 'ضيف مهم - ترتيب خاص'
      })
    })

    await this.runTest('Check-in Guest by Staff', async () => {
      if (!this.tester.bookingId) return { success: false, data: { message: 'No booking ID available' } }
      return await this.tester.makeRequest('PUT', `/staff/bookings/${this.tester.bookingId}/checkin`, {
        checkedInBy: this.tester.userId,
        checkedInAt: new Date().toISOString(),
        roomKeyProvided: true,
        documentsVerified: true
      })
    })

    await this.runTest('Check-out Guest by Staff', async () => {
      if (!this.tester.bookingId) return { success: false, data: { message: 'No booking ID available' } }
      return await this.tester.makeRequest('PUT', `/staff/bookings/${this.tester.bookingId}/checkout`, {
        checkedOutBy: this.tester.userId,
        checkedOutAt: new Date().toISOString(),
        finalBillPaid: true,
        feedbackCollected: true,
        roomInspectionCompleted: true
      })
    })

    // ROOM SEARCH TESTING (for room_search_screen.dart)
    await this.runTest('Search Available Rooms', async () => {
      if (!this.tester.hotelId) return { success: false, data: { message: 'No hotel ID available' } }
      const tomorrow = new Date(Date.now() + 24*60*60*1000).toISOString()
      const dayAfter = new Date(Date.now() + 3*24*60*60*1000).toISOString()
      
      return await this.tester.makeRequest('GET', `/rooms/search?hotelId=${this.tester.hotelId}&checkIn=${tomorrow}&checkOut=${dayAfter}&guests=2&minPrice=100&maxPrice=300`)
    })

    await this.runTest('Filter Rooms by Capacity', async () => {
      if (!this.tester.hotelId) return { success: false, data: { message: 'No hotel ID available' } }
      return await this.tester.makeRequest('GET', `/rooms/filter?hotelId=${this.tester.hotelId}&capacity=2&beds=1&amenities=WiFi,TV`)
    })

    await this.runTest('Get Room Availability Calendar', async () => {
      if (!this.tester.roomId) return { success: false, data: { message: 'No room ID available' } }
      const startDate = new Date().toISOString()
      const endDate = new Date(Date.now() + 30*24*60*60*1000).toISOString()
      return await this.tester.makeRequest('GET', `/rooms/${this.tester.roomId}/availability?start=${startDate}&end=${endDate}`)
    })

    // GUEST DASHBOARD TESTING (for guest_main_dashboard.dart)
    await this.runTest('Get Guest Dashboard Data', async () => {
      return await this.tester.makeRequest('GET', '/guest/dashboard')
    })

    await this.runTest('Get Guest Current Booking', async () => {
      return await this.tester.makeRequest('GET', '/guest/current-booking')
    })

    await this.runTest('Get Guest Booking History', async () => {
      return await this.tester.makeRequest('GET', '/guest/booking-history?limit=10&offset=0')
    })

    await this.runTest('Get Guest Active Services', async () => {
      return await this.tester.makeRequest('GET', '/guest/active-services')
    })

    await this.runTest('Get Guest Quick Actions', async () => {
      return await this.tester.makeRequest('GET', '/guest/quick-actions')
    })

    // CONTESTS TESTING
    await this.runTest('Create Contest', async () => {
      if (!this.tester.hotelId) return { success: false, data: { message: 'No hotel ID available' } }
      const response = await this.tester.makeRequest('POST', '/contests', {
        title: 'مسابقة اختبار الربيع',
        description: 'مسابقة صيفية ممتعة للجميع',
        startDate: new Date(Date.now() + 24*60*60*1000).toISOString(),
        endDate: new Date(Date.now() + 7*24*60*60*1000).toISOString(),
        prize: 'خصم 50% على الحجز القادم',
        maxParticipants: 100,
        rules: ['يجب التسجيل أولاً', 'مشاركة عبر وسائل التواصل']
      })
      
      if (response.success && response.data.data?.id) {
        this.tester.contestId = response.data.data.id
      }
      return response
    })

    await this.runTest('Get Contests', async () => {
      return await this.tester.makeRequest('GET', '/contests')
    })

    if (this.tester.contestId) {
      await this.runTest('Join Contest', async () => {
        return await this.tester.makeRequest('POST', '/contests/participate', {
          contestId: this.tester.contestId
        })
      })

      await this.runTest('Submit Contest Score', async () => {
        return await this.tester.makeRequest('POST', `/contests/${this.tester.contestId}/submit-score`, {
          score: 85,
          submissionData: 'إجابة المسابقة'
        })
      })
    }

    // GAMES TESTING
    await this.runTest('Create Game', async () => {
      const response = await this.tester.makeRequest('POST', '/games', {
        title: 'لعبة اختبار الذكاء',
        description: 'لعبة ممتعة لاختبار ذكائك',
        gameType: 'puzzle',
        difficulty: 'medium',
        rules: ['حل اللغز في أقل وقت', 'استخدم التلميحات بحكمة'],
        maxAttempts: 3
      })
      
      if (response.success && response.data.data?.id) {
        this.tester.gameId = response.data.data.id
      }
      return response
    })

    await this.runTest('Get Games', async () => {
      return await this.tester.makeRequest('GET', '/games')
    })

    if (this.tester.gameId) {
      await this.runTest('Start Game Session', async () => {
        const response = await this.tester.makeRequest('POST', '/games/sessions', {
          gameId: this.tester.gameId,
          startTime: new Date().toISOString()
        })
        
        if (response.success && response.data.data?.id) {
          this.tester.gameSessionId = response.data.data.id
        }
        return response
      })

      if (this.tester.gameSessionId) {
        await this.runTest('Update Game Session', async () => {
          return await this.tester.makeRequest('PUT', '/games/sessions/update', {
            sessionId: this.tester.gameSessionId,
            score: 75,
            level: 2,
            achievements: ['مستوى متوسط', 'لاعب مبتدئ'],
            isCompleted: false
          })
        })
      }
    }

    // RECOMMENDATIONS TESTING
    await this.runTest('Get Personalized Recommendations', async () => {
      return await this.tester.makeRequest('GET', '/recommendations')
    })

    await this.runTest('Track Recommendation Interaction', async () => {
      if (!this.tester.recommendationId) {
        return { success: false, data: { message: 'No recommendation ID available' } }
      }
      return await this.tester.makeRequest('POST', '/recommendations/interact', {
        recommendationId: this.tester.recommendationId,
        action: 'click',
        timestamp: new Date().toISOString()
      })
    })

    // ADVERTISEMENTS TESTING
    await this.runTest('Get Advertisements', async () => {
      return await this.tester.makeRequest('GET', '/advertisements')
    })

    // LOYALTY TESTING
    await this.runTest('Get Loyalty Points', async () => {
      return await this.tester.makeRequest('GET', '/loyalty/points')
    })

    await this.runTest('Get Loyalty Tiers', async () => {
      return await this.tester.makeRequest('GET', '/loyalty/tiers')
    })

    await this.runTest('Get Loyalty Transactions', async () => {
      return await this.tester.makeRequest('GET', '/loyalty/transactions')
    })

    await this.runTest('Redeem Loyalty Points', async () => {
      return await this.tester.makeRequest('POST', '/loyalty/redeem', {
        points: 100,
        reward: 'discount_10'
      })
    })

    // BIOMETRIC AUTH TESTING
    await this.runTest('Get Biometric Status', async () => {
      return await this.tester.makeRequest('GET', '/biometric/status')
    })

    await this.runTest('Setup Biometric Authentication', async () => {
      return await this.tester.makeRequest('POST', '/biometric/setup', {
        type: 'fingerprint'
      })
    })

    await this.runTest('Test Biometric Authentication', async () => {
      return await this.tester.makeRequest('POST', '/biometric/test')
    })

    await this.runTest('Disable Biometric Authentication', async () => {
      return await this.tester.makeRequest('POST', '/biometric/disable')
    })

    // Admin tests (would need admin token)
    await this.runTest('Get Admin Analytics Summary', async () => {
      return await this.tester.makeRequest('GET', '/admin/analytics/summary')
    })

    // Test cleanup
    await this.runTest('Logout', async () => {
      return await this.tester.makeRequest('POST', '/auth/logout')
    })

    this.generateReport()
  }

  generateReport() {
    console.log('\n📊 TEST RESULTS SUMMARY')
    console.log('========================')
    
    const totalTests = this.testResults.length
    const passedTests = this.testResults.filter(r => r.success).length
    const failedTests = totalTests - passedTests
    const totalDuration = this.testResults.reduce((sum, r) => sum + r.duration, 0)

    console.log(`Total Tests: ${totalTests}`)
    console.log(`✅ Passed: ${passedTests}`)
    console.log(`❌ Failed: ${failedTests}`)
    console.log(`📈 Success Rate: ${((passedTests / totalTests) * 100).toFixed(1)}%`)
    console.log(`⏱️  Total Duration: ${totalDuration}ms`)
    console.log(`⚡ Average Duration: ${(totalDuration / totalTests).toFixed(1)}ms`)

    if (failedTests > 0) {
      console.log('\n❌ FAILED TESTS:')
      this.testResults
        .filter(r => !r.success)
        .forEach(test => {
          console.log(`   - ${test.name}: ${test.message}`)
        })
    }

    // Test environment info
    console.log('\n🔧 TEST ENVIRONMENT:')
    console.log(`API Base URL: ${API_BASE_URL}`)
    console.log(`Node Environment: ${process.env.NODE_ENV || 'development'}`)
    console.log(`Test Started: ${new Date().toISOString()}`)

    // Cleanup operations
    console.log('\n🧹 CLEANUP:')
    console.log('Test data created and can be cleaned up manually or via separate cleanup script.')

    return {
      total: totalTests,
      passed: passedTests,
      failed: failedTests,
      successRate: ((passedTests / totalTests) * 100).toFixed(1),
      duration: totalDuration,
      results: this.testResults
    }
  }
}

// Performance testing
async function runPerformanceTests() {
  console.log('\n🚀 Running Performance Tests...')
  
  const tester = new APITester(API_BASE_URL)
  await tester.authenticate()
  
  const concurrentRequests = 10
  const testEndpoint = '/hotels'
  
  console.log(`Testing ${testEndpoint} with ${concurrentRequests} concurrent requests...`)
  
  const startTime = Date.now()
  const requests = Array.from({ length: concurrentRequests }, () => 
    tester.makeRequest('GET', testEndpoint)
  )
  
  const results = await Promise.all(requests)
  const endTime = Date.now()
  const totalDuration = endTime - startTime
  
  const successfulRequests = results.filter(r => r.success).length
  const failedRequests = results.length - successfulRequests
  
  console.log(`✅ Completed ${concurrentRequests} requests`)
  console.log(`⏱️  Total Duration: ${totalDuration}ms`)
  console.log(`🚀 Requests/Second: ${(concurrentRequests / (totalDuration / 1000)).toFixed(2)}`)
  console.log(`✅ Success Rate: ${((successfulRequests / concurrentRequests) * 100).toFixed(1)}%`)
  console.log(`📊 Average Response Time: ${(totalDuration / concurrentRequests).toFixed(2)}ms`)
}

// Load testing
async function runLoadTest(duration = 30000) {
  console.log('\n⚡ Running Load Test...')
  console.log(`Duration: ${duration / 1000} seconds`)
  
  const tester = new APITester(API_BASE_URL)
  await tester.authenticate()
  
  const startTime = Date.now()
  let requestCount = 0
  let errorCount = 0
  
  const testEndpoint = '/hotels'
  
  const interval = setInterval(async () => {
    try {
      const result = await tester.makeRequest('GET', testEndpoint)
      requestCount++
      if (!result.success) {
        errorCount++
      }
    } catch (error) {
      errorCount++
      console.error('Load test error:', error)
    }
  }, 1000) // 1 request per second
  
  setTimeout(() => {
    clearInterval(interval)
    const endTime = Date.now()
    const actualDuration = endTime - startTime
    
    console.log('\n📊 Load Test Results:')
    console.log(`Duration: ${(actualDuration / 1000).toFixed(2)} seconds`)
    console.log(`Total Requests: ${requestCount}`)
    console.log(`Requests/Second: ${(requestCount / (actualDuration / 1000)).toFixed(2)}`)
    console.log(`Errors: ${errorCount}`)
    console.log(`Error Rate: ${((errorCount / requestCount) * 100).toFixed(2)}%`)
    console.log(`Success Rate: ${(((requestCount - errorCount) / requestCount) * 100).toFixed(2)}%`)
  }, duration)
}

// Security testing
async function runSecurityTests() {
  console.log('\n🔒 Running Security Tests...')
  
  const tester = new APITester(API_BASE_URL)
  
  // Test without authentication
  console.log('Testing protected endpoints without auth...')
  const unauthorizedTest = await tester.makeRequest('GET', '/users/profile', null, false)
  console.log(`Unauthorized access result: ${unauthorizedTest.success ? 'FAILED' : 'PASSED'}`)
  
  // Test SQL injection prevention
  const sqlInjectionTest = await tester.makeRequest('GET', '/hotels?id=\'; DROP TABLE hotels; --', null, false)
  console.log(`SQL Injection test: ${sqlInjectionTest.status === 400 ? 'PASSED' : 'FAILED'}`)
  
  // Test XSS prevention
  const xssTest = await tester.makeRequest('POST', '/reviews', {
    hotelId: '<script>alert("xss")</script>',
    rating: '<img src=x onerror=alert(1)>',
    comment: '<script>alert("xss")</script>'
  }, false)
  console.log(`XSS Prevention test: ${xssTest.success ? 'PASSED' : 'FAILED'}`)
}

// Main execution
async function main() {
  const args = process.argv.slice(2)
  const testType = args[0] || 'all'
  
  switch (testType) {
    case 'functional':
      const suite = new HotelAPITestSuite()
      await suite.runAllTests()
      break
    case 'performance':
      await runPerformanceTests()
      break
    case 'load':
      const duration = parseInt(args[1]) || 30000
      await runLoadTest(duration)
      break
    case 'security':
      await runSecurityTests()
      break
    case 'all':
    default:
      console.log('🧪 Running Complete Test Suite...')
      const completeSuite = new HotelAPITestSuite()
      await completeSuite.runAllTests()
      await runPerformanceTests()
      await runSecurityTests()
      break
  }
}

/**
 * Advanced Admin Permission Testing Suite
 */
class AdminPermissionTestSuite extends APITester {
  constructor(baseURL) {
    super(baseURL)
    this.adminToken = ''
    this.adminUserId = ''
    this.permissionId = ''
    this.roleId = ''
  }

  async authenticateAdmin() {
    // Register admin user
    const registerResponse = await this.makeRequest('POST', '/auth/register', {
      email: `admin${Date.now()}@example.com`,
      password: 'AdminTestPass123!',
      firstName: 'Admin',
      lastName: 'Test',
      role: 'ADMIN'
    }, false)

    if (registerResponse.success && registerResponse.data.data?.token) {
      this.adminToken = registerResponse.data.data.token
      this.adminUserId = registerResponse.data.data.user.id
      return registerResponse
    }

    // Login with existing admin
    return await this.makeRequest('POST', '/auth/login', {
      email: 'admin@hotelmanagement.com',
      password: 'admin123'
    }, false)
  }

  async testPermissionEndpoints() {
    console.log('🔐 Testing Admin Permission Endpoints...')
    
    // Test GET /api/admin/permissions
    const getPermissionsResponse = await this.makeRequest(
      'GET', 
      '/admin/permissions',
      null,
      true
    )
    console.log(`✅ GET Permissions: ${getPermissionsResponse.success ? 'PASSED' : 'FAILED'}`)

    // Test POST /api/admin/permissions (Create Permission)
    const createPermissionResponse = await this.makeRequest(
      'POST',
      '/admin/permissions',
      {
        targetUserId: this.userId,
        permission: 'CREATE_USER',
        scope: 'GLOBAL',
        expiresAt: new Date(Date.now() + 24*60*60*1000).toISOString()
      },
      true
    )
    console.log(`✅ POST Create Permission: ${createPermissionResponse.success ? 'PASSED' : 'FAILED'}`)

    if (createPermissionResponse.success && createPermissionResponse.data.data?.id) {
      this.permissionId = createPermissionResponse.data.data.id
    }

    // Test PUT /api/admin/permissions (Update Permission)
    if (this.permissionId) {
      const updatePermissionResponse = await this.makeRequest(
        'PUT',
        `/admin/permissions?id=${this.permissionId}`,
        {
          canUpdate: true,
          canDelete: true,
          expiresAt: new Date(Date.now() + 48*60*60*1000).toISOString()
        },
        true
      )
      console.log(`✅ PUT Update Permission: ${updatePermissionResponse.success ? 'PASSED' : 'FAILED'}`)
    }

    // Test DELETE /api/admin/permissions (Revoke Permission)
    if (this.permissionId) {
      const deletePermissionResponse = await this.makeRequest(
        'DELETE',
        `/admin/permissions?id=${this.permissionId}`,
        null,
        true
      )
      console.log(`✅ DELETE Revoke Permission: ${deletePermissionResponse.success ? 'PASSED' : 'FAILED'}`)
    }

    return {
      getPermissionsResponse,
      createPermissionResponse
    }
  }

  async testSecurityMonitoringEndpoints() {
    console.log('🛡️  Testing Security Monitoring Endpoints...')

    // Test security logs
    const securityLogsResponse = await this.makeRequest(
      'GET',
      '/admin/security/logs',
      null,
      true
    )
    console.log(`✅ GET Security Logs: ${securityLogsResponse.success ? 'PASSED' : 'FAILED'}`)

    // Test user sessions
    const sessionsResponse = await this.makeRequest(
      'GET',
      '/admin/security/sessions',
      null,
      true
    )
    console.log(`✅ GET User Sessions: ${sessionsResponse.success ? 'PASSED' : 'FAILED'}`)

    // Test system settings
    const settingsResponse = await this.makeRequest(
      'GET',
      '/admin/system/settings',
      null,
      true
    )
    console.log(`✅ GET System Settings: ${settingsResponse.success ? 'PASSED' : 'FAILED'}`)

    return {
      securityLogsResponse,
      sessionsResponse,
      settingsResponse
    }
  }

  async testNewScreensAdminPermissions() {
    console.log('🏨 Testing Admin Permissions for New Hotel Screens...')
    
    // Room Search Management
    const roomSearchResponse = await this.makeRequest(
      'GET',
      '/admin/permissions/room-search',
      null,
      true
    )
    console.log(`✅ Room Search Admin Control: ${roomSearchResponse.success ? 'PASSED' : 'FAILED'}`)

    // Services Management
    const servicesManagementResponse = await this.makeRequest(
      'GET',
      '/admin/permissions/services-management',
      null,
      true
    )
    console.log(`✅ Services Management Admin Control: ${servicesManagementResponse.success ? 'PASSED' : 'FAILED'}`)

    // Billing & Invoice Management
    const billingManagementResponse = await this.makeRequest(
      'GET',
      '/admin/permissions/billing-management',
      null,
      true
    )
    console.log(`✅ Billing Management Admin Control: ${billingManagementResponse.success ? 'PASSED' : 'FAILED'}`)

    // Staff Booking Confirmation
    const staffBookingResponse = await this.makeRequest(
      'GET',
      '/admin/permissions/staff-booking',
      null,
      true
    )
    console.log(`✅ Staff Booking Admin Control: ${staffBookingResponse.success ? 'PASSED' : 'FAILED'}`)

    // Guest Dashboard Management
    const guestDashboardResponse = await this.makeRequest(
      'GET',
      '/admin/permissions/guest-dashboard',
      null,
      true
    )
    console.log(`✅ Guest Dashboard Admin Control: ${guestDashboardResponse.success ? 'PASSED' : 'FAILED'}`)

    // Grant specific permissions
    const grantPermissionsResponse = await this.makeRequest(
      'POST',
      '/admin/permissions/grant',
      {
        targetUserId: this.userId,
        permissions: [
          'BOOKING_CREATE',
          'BOOKING_UPDATE', 
          'BOOKING_DELETE',
          'BOOKING_READ',
          'PAYMENT_PROCESS',
          'SERVICE_MANAGE',
          'BILLING_VIEW',
          'STAFF_BOOKING_ACCESS',
          'GUEST_DASHBOARD_ACCESS'
        ],
        scope: 'HOTEL',
        hotelId: this.tester.hotelId,
        expiresAt: new Date(Date.now() + 30*24*60*60*1000).toISOString()
      },
      true
    )
    console.log(`✅ Grant Hotel Management Permissions: ${grantPermissionsResponse.success ? 'PASSED' : 'FAILED'}`)

    // Revoke specific permissions
    const revokePermissionsResponse = await this.makeRequest(
      'POST',
      '/admin/permissions/revoke',
      {
        targetUserId: this.userId,
        permissions: [
          'BOOKING_DELETE',
          'PAYMENT_PROCESS'
        ]
      },
      true
    )
    console.log(`✅ Revoke Specific Permissions: ${revokePermissionsResponse.success ? 'PASSED' : 'FAILED'}`)

    // Check user permissions
    const userPermissionsResponse = await this.makeRequest(
      'GET',
      `/admin/permissions/user/${this.userId}`,
      null,
      true
    )
    console.log(`✅ Get User Permissions: ${userPermissionsResponse.success ? 'PASSED' : 'FAILED'}`)

    // Update screen settings
    const updateScreenSettingsResponse = await this.makeRequest(
      'PUT',
      '/admin/screen-settings',
      {
        roomSearch: {
          enabled: true,
          maxGuests: 8,
          priceRange: { min: 50, max: 500 },
          defaultFilters: { capacity: 2, amenities: ['WiFi'] }
        },
        services: {
          enabled: true,
          categories: ['food', 'housekeeping', 'spa', 'transport'],
          maxOrders: 5
        },
        billing: {
          autoCalculate: true,
          taxRate: 0.15,
          currency: 'USD'
        },
        staffBooking: {
          autoConfirm: false,
          requireApproval: true,
          checkInTime: '15:00'
        }
      },
      true
    )
    console.log(`✅ Update Screen Settings: ${updateScreenSettingsResponse.success ? 'PASSED' : 'FAILED'}`)

    return {
      roomSearchResponse,
      servicesManagementResponse,
      billingManagementResponse,
      staffBookingResponse,
      guestDashboardResponse,
      grantPermissionsResponse,
      revokePermissionsResponse,
      userPermissionsResponse,
      updateScreenSettingsResponse
    }
  }

  async testPermissionValidation() {
    console.log('🔍 Testing Permission Validation...')

    // Test unauthorized access
    const unauthorizedResponse = await this.makeRequest(
      'POST',
      '/admin/permissions',
      {
        targetUserId: 'invalid-cuid',
        permission: 'INVALID_PERMISSION',
        scope: 'INVALID_SCOPE'
      },
      false // No authentication
    )
    console.log(`✅ Unauthorized Access Blocked: ${!unauthorizedResponse.success ? 'PASSED' : 'FAILED'}`)

    // Test invalid permission types
    const invalidPermissionResponse = await this.makeRequest(
      'POST',
      '/admin/permissions',
      {
        targetUserId: '12345',
        permission: 'NON_EXISTENT_PERMISSION',
        scope: 'GLOBAL'
      },
      true
    )
    console.log(`✅ Invalid Permission Validation: ${!invalidPermissionResponse.success ? 'PASSED' : 'FAILED'}`)

    return {
      unauthorizedResponse,
      invalidPermissionResponse
    }
  }

  async runAllAdminTests() {
    console.log('🚀 Starting Advanced Admin Permission Tests...\n')
    
    // Authenticate as admin
    const authResult = await this.authenticateAdmin()
    if (authResult.success) {
      this.authToken = authResult.data.data?.token || ''
      this.adminUserId = authResult.data.data?.user?.id || ''
      console.log('✅ Admin Authentication: PASSED\n')
    } else {
      console.log('❌ Admin Authentication: FAILED\n')
      return
    }

    // Run all admin permission tests
    await this.testPermissionEndpoints()
    console.log('')
    await this.testSecurityMonitoringEndpoints()
    console.log('')
    await this.testNewScreensAdminPermissions()
    console.log('')
    await this.testPermissionValidation()
    console.log('')

    console.log('🎉 Admin Permission Test Suite Completed!\n')
  }
}

// Main execution with new test types
async function main() {
  const args = process.argv.slice(2)
  const testType = args[0] || 'all'
  
  console.log('🧪 Hotel Management API Test Suite')
  console.log('=================================')
  console.log('Available test types:')
  console.log('  - functional: Core API functionality')
  console.log('  - performance: API performance testing')
  console.log('  - load: Load testing')
  console.log('  - security: Security testing')
  console.log('  - admin: Admin permission testing')
  console.log('  - permissions: Permission endpoint testing')
  console.log('  - hotel-screens: New hotel screens admin permissions')
  console.log('  - services: Services API testing')
  console.log('  - billing: Billing API testing')
  console.log('  - staff: Staff management API testing')
  console.log('  - all: Run all tests (default)')
  console.log('')
  
  switch (testType) {
    case 'functional':
      const suite = new HotelAPITestSuite()
      await suite.runAllTests()
      break
    case 'performance':
      await runPerformanceTests()
      break
    case 'load':
      const duration = parseInt(args[1]) || 30000
      await runLoadTest(duration)
      break
    case 'security':
      await runSecurityTests()
      break
    case 'admin':
      const adminSuite = new AdminPermissionTestSuite(API_BASE_URL)
      await adminSuite.runAllAdminTests()
      break
    case 'permissions':
      const permissionSuite = new AdminPermissionTestSuite(API_BASE_URL)
      await permissionSuite.testPermissionEndpoints()
      break
    case 'hotel-screens':
      const hotelScreensSuite = new AdminPermissionTestSuite(API_BASE_URL)
      await hotelScreensSuite.authenticateAdmin()
      await hotelScreensSuite.testNewScreensAdminPermissions()
      break
    case 'services':
      const suite = new HotelAPITestSuite()
      await suite.tester.authenticate()
      await suite.tester.createTestHotel()
      await suite.tester.createTestRoom()
      await suite.tester.createTestBooking()
      
      // Test services endpoints
      await suite.runTest('Get Hotel Services', async () => {
        return await suite.tester.makeRequest('GET', `/services?hotelId=${suite.tester.hotelId}`)
      })
      await suite.runTest('Create Service', async () => {
        return await suite.tester.makeRequest('POST', '/services', {
          hotelId: suite.tester.hotelId,
          name: 'خدمة اختبار',
          description: 'وصف الخدمة',
          category: 'housekeeping',
          price: 50.0,
          duration: 60
        })
      })
      break
    case 'billing':
      const billingSuite = new HotelAPITestSuite()
      await billingSuite.tester.authenticate()
      await billingSuite.tester.createTestHotel()
      await billingSuite.tester.createTestRoom()
      await billingSuite.tester.createTestBooking()
      
      // Test billing endpoints
      await billingSuite.runTest('Calculate Booking Bill', async () => {
        return await billingSuite.tester.makeRequest('GET', `/billing/calculate/${billingSuite.tester.bookingId}`)
      })
      break
    case 'staff':
      const staffSuite = new HotelAPITestSuite()
      await staffSuite.tester.authenticate()
      await staffSuite.tester.createTestHotel()
      await staffSuite.tester.createTestRoom()
      await staffSuite.tester.createTestBooking()
      
      // Test staff endpoints
      await staffSuite.runTest('Get Staff Dashboard', async () => {
        return await staffSuite.tester.makeRequest('GET', '/staff/bookings/dashboard')
      })
      break
    case 'all':
    default:
      console.log('🧪 Running Complete Test Suite...')
      const completeSuite = new HotelAPITestSuite()
      await completeSuite.runAllTests()
      await runPerformanceTests()
      await runSecurityTests()
      
      console.log('\n🧪 Running Advanced Admin Tests...')
      const adminTestSuite = new AdminPermissionTestSuite(API_BASE_URL)
      await adminTestSuite.runAllAdminTests()
      break
  }
}

// Export for programmatic use
export { 
  HotelAPITestSuite, 
  APITester, 
  AdminPermissionTestSuite,
  runPerformanceTests, 
  runLoadTest, 
  runSecurityTests 
}

// Run if called directly
if (require.main === module) {
  main().catch(console.error)
}