/**
 * Post-build script for Vercel deployment
 * Runs after npm run build to perform final optimizations
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🚀 Running post-build optimizations for Vercel...');

// Check if build was successful
const buildPath = path.join(process.cwd(), '.next');
if (!fs.existsSync(buildPath)) {
  console.error('❌ Build directory not found. Build may have failed.');
  process.exit(1);
}

try {
  // Generate Prisma client if needed
  console.log('📦 Generating Prisma client...');
  execSync('npx prisma generate', { stdio: 'inherit' });
  
  // Verify critical files exist
  const criticalFiles = [
    'package.json',
    'next.config.mjs',
    'prisma/schema.prisma'
  ];
  
  let allFilesExist = true;
  for (const file of criticalFiles) {
    if (!fs.existsSync(file)) {
      console.error(`❌ Missing critical file: ${file}`);
      allFilesExist = false;
    }
  }
  
  if (!allFilesExist) {
    console.error('❌ Critical files missing. Deployment may fail.');
    process.exit(1);
  }
  
  // Create .env.example if it doesn't exist
  const envExamplePath = '.env.example';
  if (!fs.existsSync(envExamplePath)) {
    const envExample = `# Environment Variables Template
# Copy this file to .env.local and fill in your values

# Database
DATABASE_URL=postgresql://username:password@localhost:5432/hotel_management

# Authentication
NEXTAUTH_SECRET=your-secret-key-here
NEXTAUTH_URL=https://yourdomain.com

# Stripe (Payments)
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

# Email (Optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# File Upload
UPLOAD_PROVIDER=local
AWS_ACCESS_KEY_ID=your-aws-key
AWS_SECRET_ACCESS_KEY=your-aws-secret
AWS_BUCKET_NAME=your-bucket

# Security
ENCRYPTION_KEY=your-32-character-key
JWT_SECRET=your-jwt-secret

# API Keys
GOOGLE_MAPS_API_KEY=your-google-maps-key
SENDGRID_API_KEY=your-sendgrid-key

# Admin Settings
ADMIN_EMAIL=admin@hotelmanagement.com
ADMIN_PASSWORD=admin123

# Rate Limiting
RATE_LIMIT_WINDOW=15
RATE_LIMIT_MAX=100

# CORS
ALLOWED_ORIGINS=https://yourdomain.com,https://localhost:3000
`;
    fs.writeFileSync(envExamplePath, envExample);
    console.log('✅ Created .env.example template');
  }
  
  // Verify Next.js build output
  const serverBuildExists = fs.existsSync(path.join(buildPath, 'server'));
  const staticExists = fs.existsSync(path.join(buildPath, 'static'));
  
  if (!serverBuildExists) {
    console.error('❌ Server build not found.');
    process.exit(1);
  }
  
  console.log('✅ Build verification completed');
  console.log('🎉 Post-build optimization complete! Ready for Vercel deployment.');
  
  // Display deployment info
  console.log('\n📋 Deployment Checklist:');
  console.log('   ✅ Next.js build successful');
  console.log('   ✅ Prisma client generated');
  console.log('   ✅ Critical files verified');
  console.log('   ✅ Environment template created');
  console.log('\n🚀 Ready to deploy to Vercel!');
  
} catch (error) {
  console.error('❌ Post-build script failed:', error.message);
  process.exit(1);
}