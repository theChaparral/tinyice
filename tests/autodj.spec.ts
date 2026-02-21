import { test, expect } from '@playwright/test';

// Use a unique mount for each run to avoid conflicts
const TEST_MOUNT = `/test-dj-${Math.floor(Math.random() * 1000)}`;
const TEST_NAME = 'Playwright Automation DJ';

test.describe('TinyIce AutoDJ Professional Workflow', () => {
  
  test.beforeEach(async ({ page }) => {
    // Navigate directly to admin - auth is handled by config extraHTTPHeaders
    await page.goto('/admin');
    // Ensure we are actually on the admin page
    await expect(page).toHaveTitle(/TinyIce Admin/);
  });

  test('E2E: Provision, Browse, Curate, and Control AutoDJ', async ({ page, baseURL }) => {
    // 1. Navigate to AutoDJ Section
    const autodjNav = page.locator('button.nav-link:has-text("AutoDJ")');
    await autodjNav.click();
    await expect(page.locator('h1.page-title')).toContainText('AutoDJ');

    // 2. Provision New AutoDJ
    console.log(`Provisioning AutoDJ on ${TEST_MOUNT}...`);
    await page.fill('input[name="name"]', TEST_NAME);
    await page.fill('input[name="mount"]', TEST_MOUNT);
    await page.fill('input[name="music_dir"]', './music'); 
    
    await page.check('input[name="loop"]');
    await page.check('input[name="inject_metadata"]');
    await page.check('input[name="visible"]');
    
    // Test MPD Toggle
    await page.check('input[name="mpd_enabled"]');
    await page.fill('input[name="mpd_port"]', '6699');

    await page.click('button:has-text("Create AutoDJ")');

    // 3. Verify Success Feedback Overlay
    const overlay = page.locator('#action-overlay');
    await expect(overlay).toBeVisible();
    await expect(page.locator('#action-text')).toContainText('Success');
    
    // Wait for the overlay to disappear and page to reload (structural change)
    await expect(overlay).not.toBeVisible({ timeout: 10000 });
    
    // 4. Find our new card
    const card = page.locator(`.autodj-card[data-mount="${TEST_MOUNT}"]`);
    await expect(card).toBeVisible();
    await expect(card).toContainText(TEST_NAME);
    await expect(card).toContainText('PORT 6699');

    // 5. Library Browser - Add songs without reload
    console.log('Testing recursive library browser...');
    await card.getByRole('button', { name: 'BROWSE FILES' }).click();
    
    // Wait for internal spinner
    await expect(card.locator('.spinner')).toBeVisible();
    await expect(card.locator('.spinner')).not.toBeVisible();

    // Add the first found .mp3
    const firstAddBtn = card.locator('button:has-text("ADD")').first();
    await expect(firstAddBtn).toBeVisible();
    await firstAddBtn.click();

    // Verify Success Overlay (AJAX action)
    await expect(overlay).toBeVisible();
    await expect(page.locator('#action-text')).toContainText('Success');
    await expect(overlay).not.toBeVisible();

    // 6. Verify Playlist Position (it might take a moment for SSE to sync)
    await expect(card.locator('.adj-len')).toHaveText('1', { timeout: 5000 });

    // 7. Test Transport Controls (AJAX - No Reload)
    console.log('Testing transport controls...');
    
    // Start it
    await card.getByRole('button', { name: 'START' }).click();
    await expect(overlay).toBeVisible();
    await expect(overlay).not.toBeVisible();
    await expect(card.locator('.adj-status-text')).toHaveText('LIVE', { timeout: 5000 });

    // Toggle Shuffle
    const shuffleBtn = card.locator('.adj-shuffle-btn');
    await shuffleBtn.click();
    await expect(shuffleBtn).toHaveClass(/btn-primary/); // Should be active

    // Toggle Loop
    const loopBtn = card.locator('.adj-loop-btn');
    await loopBtn.click();
    await expect(loopBtn).toHaveClass(/btn-primary/); // Should be active

    // Skip Next
    const skipBtn = card.locator('button[title="Skip to Next"]');
    await expect(skipBtn).toBeVisible();
    await skipBtn.click();
    await expect(overlay).toBeVisible();
    await expect(page.locator('#action-text')).toContainText('Success');

    // 8. Test the Edit Modal
    console.log('Testing Edit Modal...');
    await card.locator('button[title="Edit AutoDJ"]').click();
    const modal = page.locator('#edit-autodj-modal');
    await expect(modal).toBeVisible();
    
    // Change name
    await page.fill('#edit-name', TEST_NAME + ' (Updated)');
    await page.click('#edit-autodj-form button[type="submit"]');
    
    await expect(overlay).toBeVisible();
    await expect(overlay).not.toBeVisible();
    await expect(card).toContainText('Updated');

    // 9. Cleanup - Delete
    console.log('Cleaning up...');
    // Setup listener for the browser confirm dialog
    page.once('dialog', dialog => dialog.accept());
    await card.getByRole('button', { name: 'DELETE' }).click();
    
    await expect(overlay).toBeVisible();
    await expect(overlay).not.toBeVisible();
    await expect(card).not.toBeVisible();
  });

});
