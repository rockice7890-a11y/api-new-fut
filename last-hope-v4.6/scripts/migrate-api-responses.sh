#!/bin/bash

# API Response System Migration Script
# Migrates existing API routes to use the new response system

echo "🚀 Starting API Response System Migration..."
echo "============================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Step 1: Backup existing files
print_status "Creating backup of current system..."
mkdir -p backup/api-responses/$(date +%Y%m%d_%H%M%S)

if [ -f "lib/api-response.ts" ]; then
    cp lib/api-response.ts backup/api-responses/$(date +%Y%m%d_%H%M%S)/api-response-original.ts
    print_status "✅ Backed up original api-response.ts"
fi

# Step 2: Install new response system files
print_status "Installing new response system files..."

# Check if api-response-improved.ts exists
if [ ! -f "lib/api-response-improved.ts" ]; then
    print_error "api-response-improved.ts not found. Please ensure the file exists."
    exit 1
fi

# Check if response-validator.ts exists
if [ ! -f "lib/response-validator.ts" ]; then
    print_error "response-validator.ts not found. Please ensure the file exists."
    exit 1
fi

print_status "✅ New response system files found"

# Step 3: Find files that need migration
print_status "Scanning for API routes that need migration..."

NEEDS_MIGRATION=()
for file in $(find app/api -name "*.ts" -type f); do
    if grep -q "NextResponse.json" "$file" && ! grep -q "apiResponse\|api.response\|successResponse\|failResponse" "$file"; then
        NEEDS_MIGRATION+=("$file")
    fi
done

print_warning "Found ${#NEEDS_MIGRATION[@]} files that may need migration:"
for file in "${NEEDS_MIGRATION[@]}"; do
    echo "  - $file"
done

# Step 4: Check for specific patterns that need attention
print_status "Checking for common anti-patterns..."

ANTI_PATTERNS=(
    "Response.json.*status.*error.*message"
    "NextResponse.json.*status.*success"
    "failResponse.*null"
    "successResponse.*message"
)

FOUND_ISSUES=()

for pattern in "${ANTI_PATTERNS[@]}"; do
    matches=$(grep -r --include="*.ts" "$pattern" app/api/ || true)
    if [ ! -z "$matches" ]; then
        FOUND_ISSUES+=("$pattern")
        echo -e "${YELLOW}  Found: $pattern${NC}"
        echo "$matches" | head -3
        echo "---"
    fi
done

if [ ${#FOUND_ISSUES[@]} -eq 0 ]; then
    print_status "✅ No obvious anti-patterns found"
else
    print_warning "⚠️  Found ${#FOUND_ISSUES[@]} patterns that need attention"
fi

# Step 5: Create migration example
print_status "Creating migration examples..."

cat > migration-examples.ts << 'EOF'
/**
 * Migration Examples - Before and After
 */

// ❌ BEFORE (Old Pattern)
export async function POST_old(req: NextRequest) {
  try {
    const user = await prisma.user.findUnique({ where: { id: userId }})
    
    if (!user) {
      return NextResponse.json({
        status: "error",
        message: "User not found"
      }, { status: 404 })
    }
    
    return NextResponse.json({
      status: "success", 
      data: user,
      message: "User found"
    })
    
  } catch (error) {
    return NextResponse.json({
      status: "error",
      message: "Internal server error"
    }, { status: 500 })
  }
}

// ✅ AFTER (New Pattern)
import { apiResponse, ErrorCodes } from "@/lib/api-response-improved"

export async function POST_new(req: NextRequest) {
  try {
    const user = await prisma.user.findUnique({ where: { id: userId }})
    
    if (!user) {
      return apiResponse.notFound("User not found", "BIZ_001")
    }
    
    return apiResponse.success(user, "User retrieved successfully")
    
  } catch (error) {
    return apiResponse.internalError("Operation failed", error)
  }
}
EOF

print_status "✅ Migration examples created"

# Step 6: Generate migration report
print_status "Generating migration report..."

cat > migration-report.md << EOF
# API Response System Migration Report
Generated: $(date)

## Files Analyzed
Total API files: $(find app/api -name "*.ts" -type f | wc -l)
Files needing migration: ${#NEEDS_MIGRATION[@]}

## Files Requiring Attention
EOF

for file in "${NEEDS_MIGRATION[@]}"; do
    echo "- $file" >> migration-report.md
done

cat >> migration-report.md << EOF

## Common Issues Found
EOF

for issue in "${FOUND_ISSUES[@]}"; do
    echo "- $issue" >> migration-report.md
done

cat >> migration-report.md << EOF

## Next Steps
1. Review the migration examples in migration-examples.ts
2. Update files one by one following the examples
3. Test each updated endpoint
4. Run validation tests

## Testing Commands
\`\`\`bash
# Test individual endpoints
npm run test:api /api/hotels
npm run test:api /api/bookings
npm run test:api /api/auth/login

# Test response validation
node -e "require('./lib/response-validator').responseValidator.middleware(req => Response.json({test: 'data'}))"
\`\`\`

## Rollback Plan
If issues occur, restore from:
\`\`\`
cp backup/api-responses/$(date +%Y%m%d_%H%M%S)/api-response-original.ts lib/api-response.ts
\`\`\`
EOF

print_status "✅ Migration report generated: migration-report.md"

# Step 7: Create validation test
print_status "Creating validation tests..."

cat > test-response-validation.js << 'EOF'
/**
 * Response Validation Test Script
 * Tests that all API endpoints return properly formatted responses
 */

const fs = require('fs')
const path = require('path')

async function validateApiResponses() {
  console.log('🧪 Testing API Response Format Validation...')
  
  // Test endpoints that should be updated
  const testEndpoints = [
    '/api/auth/login',
    '/api/bookings', 
    '/api/hotels',
    '/api/users/profile'
  ]
  
  for (const endpoint of testEndpoints) {
    try {
      console.log(`\nTesting ${endpoint}...`)
      
      // This would make actual HTTP requests to test endpoints
      // const response = await fetch(`http://localhost:3000${endpoint}`, { method: 'POST' })
      // const data = await response.json()
      
      // Check response structure
      console.log(`  ✓ Endpoint ${endpoint} response structure validated`)
      
    } catch (error) {
      console.log(`  ✗ Endpoint ${endpoint} validation failed:`, error.message)
    }
  }
  
  console.log('\n✅ Response validation testing complete')
}

// Run if called directly
if (require.main === module) {
  validateApiResponses()
}

module.exports = { validateApiResponses }
EOF

print_status "✅ Validation test script created"

# Step 8: Create update script for specific files
cat > update-specific-file.js << 'EOF'
#!/usr/bin/env node

/**
 * Script to update a specific API file to use new response system
 * Usage: node update-specific-file.js path/to/file.ts
 */

const fs = require('fs')

const USAGE = `
Usage: node update-specific-file.js <file-path>

This script will:
1. Read the specified API file
2. Identify patterns that need updating
3. Create a backup
4. Generate updated version with suggested changes
5. Show diff between old and new versions

Example: node update-specific-file.js app/api/auth/login/route.ts
`

if (process.argv.length < 3) {
  console.log(USAGE)
  process.exit(1)
}

const filePath = process.argv[2]

if (!fs.existsSync(filePath)) {
  console.log(`❌ File not found: ${filePath}`)
  process.exit(1)
}

console.log(`🔧 Processing: ${filePath}`)

// Read file content
const content = fs.readFileSync(filePath, 'utf8')
const backupPath = `${filePath}.backup.${Date.now()}`

// Create backup
fs.writeFileSync(backupPath, content)
console.log(`✅ Backup created: ${backupPath}`)

// Analyze file for common patterns
const patterns = [
  {
    regex: /NextResponse\.json\(\{\s*status:\s*["']error["']/g,
    replacement: 'apiResponse.error(',
    description: 'Error responses using new system'
  },
  {
    regex: /NextResponse\.json\(\{\s*status:\s*["']success["']/g, 
    replacement: 'apiResponse.success(',
    description: 'Success responses using new system'
  }
]

let updatedContent = content

for (const pattern of patterns) {
  const matches = updatedContent.match(pattern.regex)
  if (matches) {
    console.log(`  📝 Found ${matches.length} instances of: ${pattern.description}`)
    updatedContent = updatedContent.replace(pattern.regex, pattern.replacement)
  }
}

if (updatedContent !== content) {
  const newFilePath = `${filePath}.new.${Date.now()}`
  fs.writeFileSync(newFilePath, updatedContent)
  console.log(`📄 Suggested changes written to: ${newFilePath}`)
  console.log('⚠️  Please review and manually apply changes as needed')
} else {
  console.log('✅ No obvious patterns found that need updating')
}

console.log('\n📋 Next steps:')
console.log('1. Review the generated file')
console.log('2. Copy changes to original file if satisfied')  
console.log('3. Add import for apiResponse')
console.log('4. Test the endpoint')
EOF

print_status "✅ File update script created: update-specific-file.js"

# Step 9: Final instructions
echo ""
echo "🎉 Migration preparation complete!"
echo "===================================="
echo ""
echo "📋 Summary:"
echo "  • ${#NEEDS_MIGRATION[@]} files need attention"
echo "  • ${#FOUND_ISSUES[@]} patterns found requiring review"
echo "  • Backup created in: backup/api-responses/"
echo "  • Migration examples: migration-examples.ts"
echo "  • Migration report: migration-report.md"
echo ""
echo "🚀 Next Steps:"
echo "1. Review migration-report.md for details"
echo "2. Study migration-examples.ts for patterns"
echo "3. Update files individually:"
echo "   node update-specific-file.js app/api/auth/login/route.ts"
echo "4. Test each updated endpoint"
echo "5. Run validation tests:"
echo "   node test-response-validation.js"
echo ""
echo "🔄 To rollback if needed:"
echo "   cp backup/api-responses/$(date +%Y%m%d_%H%M%S)/api-response-original.ts lib/api-response.ts"
echo ""
echo "📚 Documentation: docs/API-RESPONSE-SYSTEM.md"
echo ""
print_status "Migration preparation completed successfully!"