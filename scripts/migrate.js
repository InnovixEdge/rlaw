const { execSync } = require('child_process');

if (process.env.MIGRATE_ON_BUILD === 'true') {
  console.log('🔄 Running database migration...');
  try {
    execSync('npx prisma db push', { stdio: 'inherit' });
    execSync('node scripts/init-db.js', { stdio: 'inherit' });
    console.log('✅ Database migration completed!');
  } catch (error) {
    console.error('❌ Migration failed:', error);
    process.exit(1);
  }
}
