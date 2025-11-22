import { NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'

// Simple health check endpoint - no database required
export async function GET() {
  try {
    const healthStatus = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'Hotel Management API',
      version: '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      checks: {
        api: 'operational',
        database: process.env.DATABASE_URL ? 'configured' : 'not_configured',
        jwt: process.env.JWT_SECRET ? 'configured' : 'not_configured',
        nextauth: process.env.NEXTAUTH_SECRET ? 'configured' : 'not_configured',
      }
    }

    return NextResponse.json({
      status: 'success',
      data: healthStatus,
      message: 'API is running successfully'
    }, { status: 200 })
  } catch (error) {
    return NextResponse.json({
      status: 'error',
      message: 'Health check failed'
    }, { status: 500 })
  }
}

export async function POST() {
  return NextResponse.json({
    status: 'success',
    message: 'Health endpoint is working - POST method',
    timestamp: new Date().toISOString()
  })
}
