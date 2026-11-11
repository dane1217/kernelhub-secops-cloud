import { test, expect } from '@playwright/test';

test('unauthenticated users see the OIDC sign-in flow', async ({page})=>{
  await page.goto('/');
  await expect(page.getByRole('link',{name:/sign in securely/i})).toHaveAttribute('href','/auth/login');
  await expect(page.getByText('Multi-factor authentication is managed by your identity provider.')).toBeVisible();
});

test('empty tenant dashboard uses API data and labels deferred capabilities', async ({page})=>{
  // Explicit HTTP fixture: browser behavior test, not a claim of real OIDC/stack validation.
  await page.route('**/api/me',r=>r.fulfill({json:{user_id:'test',email:'analyst@example.test',csrf:'test',platform_admin:false,product_name:'Pilot SOC',environment:'test'}}));
  await page.route('**/api/orgs',r=>r.fulfill({json:[{id:'tenant-test',name:'Synthetic test tenant',role:'viewer'}]}));
  await page.route('**/api/orgs/tenant-test/overview',r=>r.fulfill({json:{events:{total:0,last_received:null},incidents:[],alerts:[],pipeline:[],storage:{database_payload_bytes:0},worker:null,limits:{quota_daily:1000,rate_minute:100,retention_days:30},data_note:'Synthetic browser fixture'}}));
  await page.goto('/');
  await expect(page.getByText('No open incidents')).toBeVisible();
  await page.getByRole('button',{name:/exposure monitoring/i}).click();
  await expect(page.getByText('No intelligence provider is connected.',{exact:false})).toBeVisible();
  await page.getByRole('button',{name:/platform administration/i}).click();
  await expect(page.getByRole('heading',{name:'Permission denied'})).toBeVisible();
});
