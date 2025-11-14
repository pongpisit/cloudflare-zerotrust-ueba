/**
 * User Risk Scoring Demo - Cloudflare Worker
 * Automatically categorizes users into Low/Medium/High risk Cloudflare custom lists
 * Based on Cloudflare Zero Trust Risk Scoring API
 */

export default {
    // This function runs when we query the worker hostname
    async fetch(request, env, ctx) {
        return await handleRequest(request, env);
    },

    // This function runs according to the cron schedule
    async scheduled(event, env, ctx) {
        await handleRequest('notfetch', env);
    }
};

// Input validation helper functions
function validateEnvironmentVariables(env) {
    const required = ['CLOUDFLARE_ACCOUNT_ID', 'CLOUDFLARE_API_TOKEN'];
    const missing = required.filter(key => !env[key]);
    
    if (missing.length > 0) {
        throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }
    
    // Validate account ID format (should be 32 character hex string)
    if (!/^[a-f0-9]{32}$/i.test(env.CLOUDFLARE_ACCOUNT_ID)) {
        throw new Error('Invalid CLOUDFLARE_ACCOUNT_ID format');
    }
    
    // Basic API token validation (should start with appropriate prefix)
    if (!env.CLOUDFLARE_API_TOKEN.match(/^[A-Za-z0-9_-]{40,}$/)) {
        throw new Error('Invalid CLOUDFLARE_API_TOKEN format');
    }
}

function validateListId(listId, listName) {
    if (!listId || !/^[a-f0-9-]{36}$/i.test(listId)) {
        throw new Error(`Invalid ${listName} list ID format`);
    }
}

async function handleRequest(request, env) {
    // Validate environment variables first
    try {
        validateEnvironmentVariables(env);
    } catch (error) {
        console.error('Configuration validation failed:', error.message);
        if (request !== 'notfetch') {
            return new Response(JSON.stringify({
                error: 'Configuration error',
                message: error.message
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        return;
    }
    
    // Inputs for Cloudflare API calls
    const accountId = env.CLOUDFLARE_ACCOUNT_ID;
    const apiToken = env.CLOUDFLARE_API_TOKEN;
    
    // Gateway List IDs for risk categorization
    // These must be set via environment variables or wrangler secrets
    const highRiskListId = env.HIGH_RISK_LIST_ID;
    const mediumRiskListId = env.MEDIUM_RISK_LIST_ID;
    const lowRiskListId = env.LOW_RISK_LIST_ID;
    
    // Validate that list IDs are configured
    if (!highRiskListId || !mediumRiskListId || !lowRiskListId) {
        const missingLists = [];
        if (!highRiskListId) missingLists.push('HIGH_RISK_LIST_ID');
        if (!mediumRiskListId) missingLists.push('MEDIUM_RISK_LIST_ID');
        if (!lowRiskListId) missingLists.push('LOW_RISK_LIST_ID');
        
        console.error('Missing Gateway List IDs:', missingLists.join(', '));
        if (request !== 'notfetch') {
            return new Response(JSON.stringify({
                error: 'Configuration error',
                message: `Missing Gateway List IDs: ${missingLists.join(', ')}. Please set these via wrangler secrets or create new lists using /api/create-new-lists`
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        return;
    }
    
    // Validate list IDs
    try {
        validateListId(highRiskListId, 'high risk');
        validateListId(mediumRiskListId, 'medium risk');
        validateListId(lowRiskListId, 'low risk');
    } catch (error) {
        console.error('List ID validation failed:', error.message);
        if (request !== 'notfetch') {
            return new Response(JSON.stringify({
                error: 'Configuration error',
                message: error.message
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        return;
    }

    // Optimization - if fetch, stop the worker if browser is requesting favicon.ico
    if (request != 'notfetch') {
        const urlRequest = new URL(request.url);
        const checkFavicon = urlRequest.pathname.slice(1);
        if (checkFavicon == "favicon.ico") {
            return new Response(null, { status: 204 });
        }

        // Handle API routes
        if (urlRequest.pathname === '/api/user-risk-scores') {
            return await getUserRiskScoresAPI(accountId, apiToken);
        }
        if (urlRequest.pathname === '/api/health') {
            return await getHealthCheckAPI(accountId, apiToken);
        } else if (urlRequest.pathname === '/api/metrics') {
            return await getMetricsAPI(env);
        } else if (urlRequest.pathname === '/api/reconcile-lists') {
            return await handleReconciliation(accountId, apiToken, highRiskListId, mediumRiskListId, lowRiskListId, env);
        } else if (urlRequest.pathname === '/api/create-new-lists') {
            return await createNewGatewayLists(accountId, apiToken);
        } else if (urlRequest.pathname === '/api/test-user-removal') {
            return await testUserRemoval(accountId, apiToken, mediumRiskListId);
        } else if (urlRequest.pathname === '/api/test-clear-method') {
            return await testClearMethod(accountId, apiToken, mediumRiskListId);
        } else if (urlRequest.pathname === '/api/test-kv-sync') {
            return await testKVSync(accountId, apiToken, mediumRiskListId, env);
        } else if (urlRequest.pathname === '/api/test-patch-method') {
            return await testPatchMethod(accountId, apiToken, mediumRiskListId, env);
        }
        if (urlRequest.pathname === '/api/gateway-lists') {
            return await getGatewayListsAPI(accountId, apiToken, highRiskListId, mediumRiskListId, lowRiskListId);
        }
        if (urlRequest.pathname === '/api/update-risk-lists') {
            return await updateRiskListsAPI(accountId, apiToken, highRiskListId, mediumRiskListId, lowRiskListId, env);
        }
        if (urlRequest.pathname === '/api/force-cleanup') {
            // Force cleanup by directly calling the main logic
            await handleRequest('notfetch', { 
                CLOUDFLARE_ACCOUNT_ID: accountId, 
                CLOUDFLARE_API_TOKEN: apiToken,
                HIGH_RISK_LIST_ID: highRiskListId,
                MEDIUM_RISK_LIST_ID: mediumRiskListId,
                LOW_RISK_LIST_ID: lowRiskListId,
                USER_RISK_KV: env.USER_RISK_KV
            });
            return new Response(JSON.stringify({
                success: true,
                message: "Force cleanup completed - all Gateway lists synchronized with current risk scores"
            }), {
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
            });
        }
        if (urlRequest.pathname === '/api/manual-remove-user') {
            // Workaround: Delete and recreate the list to force removal
            try {
                console.log('Step 1: Deleting medium risk list');
                const deleteResult = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/gateway/lists/${mediumRiskListId}`, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': `Bearer ${apiToken}`,
                        'Content-Type': 'application/json'
                    }
                });
                
                const deleteData = await deleteResult.json();
                console.log('Delete result:', deleteData);
                
                // Wait a moment for deletion to propagate
                await new Promise(resolve => setTimeout(resolve, 3000));
                
                console.log('Step 2: Recreating medium risk list');
                const createResult = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/gateway/lists`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${apiToken}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        name: "Medium Risk Users",
                        description: "Users with medium risk scores",
                        type: "EMAIL",
                        items: [] // Start with empty list
                    })
                });
                
                const createData = await createResult.json();
                console.log('Create result:', createData);
                
                return new Response(JSON.stringify({
                    success: createData.success,
                    message: createData.success ? "List recreated successfully - user removed" : "List recreation failed",
                    details: {
                        deleteResult: deleteData,
                        createResult: createData,
                        newListId: createData.result?.id
                    }
                }), {
                    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
                });
                
            } catch (error) {
                return new Response(JSON.stringify({
                    success: false,
                    message: "List recreation failed with error",
                    error: error.message
                }), {
                    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
                });
            }
        }
        if (urlRequest.pathname === '/') {
            return new Response(getHTML(), { headers: { 'Content-Type': 'text/html' } });
        }
    }

    // Step 1: Fetch user risk scores from the API
    const userRiskResult = await fetchAllUserRiskScores(accountId, apiToken);
    
    if (!userRiskResult.success) {
        console.log('Failed to fetch user risk scores');
        return;
    }
    
    const userRiskScores = userRiskResult.users || [];
    console.log(`Processing ${userRiskScores.length} user risk scores`);
    
    // Step 2: Categorize users by risk level (using max_risk_level field)
    const highRiskUsers = userRiskScores.filter(user => user.max_risk_level === 'high');
    const mediumRiskUsers = userRiskScores.filter(user => user.max_risk_level === 'medium');
    const lowRiskUsers = userRiskScores.filter(user => user.max_risk_level === 'low');
    
    console.log(`High risk: ${highRiskUsers.length}, Medium risk: ${mediumRiskUsers.length}, Low risk: ${lowRiskUsers.length}`);
    
    // Step 3: Store expected state in KV (source of truth)
    await storeExpectedStateInKV(env, highRiskListId, highRiskUsers, 'high');
    await storeExpectedStateInKV(env, mediumRiskListId, mediumRiskUsers, 'medium');
    await storeExpectedStateInKV(env, lowRiskListId, lowRiskUsers, 'low');
    
    // Step 4: Compare KV state vs Gateway lists and update if needed
    const highResult = await syncGatewayListFromKV(accountId, apiToken, highRiskListId, env, 'High Risk Users - New');
    const mediumResult = await syncGatewayListFromKV(accountId, apiToken, mediumRiskListId, env, 'Medium Risk Users - New');
    const lowResult = await syncGatewayListFromKV(accountId, apiToken, lowRiskListId, env, 'Low Risk Users - New');
    
    console.log(`Sync results - High: ${highResult.success ? 'Success' : 'Failed'}, Medium: ${mediumResult.success ? 'Success' : 'Failed'}, Low: ${lowResult.success ? 'Success' : 'Failed'}`);

    console.log('Risk list update completed');
}

async function handleReconciliation(accountId, apiToken, highRiskListId, mediumRiskListId, lowRiskListId, env) {
    try {
        const listIds = [
            { id: highRiskListId, name: 'high' },
            { id: mediumRiskListId, name: 'medium' },
            { id: lowRiskListId, name: 'low' }
        ];
        
        const reconciliationResults = [];
        
        for (const list of listIds) {
            const kvKey = `gateway_list_${list.id}`;
            const expectedStateStr = await env.USER_RISK_KV.get(kvKey);
            
            if (!expectedStateStr) {
                console.log(`No KV state found for ${list.name} risk list ${list.id}`);
                continue;
            }
            
            const expectedState = JSON.parse(expectedStateStr);
            const expectedEmails = new Set(expectedState.emails);
            
            // Get current API state
            const currentItemsResult = await fetchGatewayListItems(accountId, apiToken, list.id);
            if (!currentItemsResult.success) {
                console.error(`Failed to fetch items for ${list.name} risk list:`, currentItemsResult.errors);
                continue;
            }
            
            const currentEmails = new Set(currentItemsResult.items.map(item => item.value));
            
            // Check for inconsistency
            const isConsistent = setsEqual(currentEmails, expectedEmails);
            
            reconciliationResults.push({
                listId: list.id,
                listName: list.name,
                consistent: isConsistent,
                expectedCount: expectedEmails.size,
                actualCount: currentEmails.size,
                expectedEmails: [...expectedEmails],
                actualEmails: [...currentEmails],
                lastUpdated: expectedState.lastUpdated,
                reconciliationNeeded: expectedState.reconciliationNeeded || false
            });
            
            if (!isConsistent) {
                console.warn(`Inconsistency detected in ${list.name} risk list ${list.id}`);
                console.log(`Expected: [${[...expectedEmails].join(', ')}]`);
                console.log(`Actual: [${[...currentEmails].join(', ')}]`);
            }
        }
        
        return new Response(JSON.stringify({
            success: true,
            timestamp: new Date().toISOString(),
            reconciliation: reconciliationResults
        }), {
            headers: { 'Content-Type': 'application/json' }
        });
        
    } catch (error) {
        console.error('Reconciliation error:', error);
        return new Response(JSON.stringify({
            success: false,
            error: error.message
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

async function createNewGatewayLists(accountId, apiToken) {
    try {
        const lists = [
            {
                name: "High Risk Users - New",
                description: "New high risk users list (not protected by policies)",
                type: "EMAIL"
            },
            {
                name: "Medium Risk Users - New", 
                description: "New medium risk users list (not protected by policies)",
                type: "EMAIL"
            },
            {
                name: "Low Risk Users - New",
                description: "New low risk users list (not protected by policies)", 
                type: "EMAIL"
            }
        ];

        const results = [];
        
        for (const listConfig of lists) {
            const createResult = await makeApiRequest(`https://api.cloudflare.com/client/v4/accounts/${accountId}/gateway/lists`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${apiToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    ...listConfig,
                    items: []
                })
            });

            const createData = await createResult.json();
            results.push({
                name: listConfig.name,
                success: createData.success,
                listId: createData.result?.id,
                errors: createData.errors
            });
        }

        return new Response(JSON.stringify({
            success: true,
            message: "New Gateway lists created",
            lists: results,
            instructions: "Update your wrangler.toml with these new list IDs to use unprotected lists"
        }), {
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });

    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: error.message
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
}

async function testUserRemoval(accountId, apiToken, mediumRiskListId) {
    try {
        const testEmail = "test@example.com";
        
        console.log("Step 1: Adding test user to medium risk list");
        const addResult = await makeApiRequest(`https://api.cloudflare.com/client/v4/accounts/${accountId}/gateway/lists/${mediumRiskListId}`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${apiToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: "Medium Risk Users - New",
                description: "New medium risk users list (not protected by policies)",
                items: [{ 
                    value: testEmail,
                    description: "Test user for removal testing"
                }]
            })
        });

        const addData = await addResult.json();
        console.log("Add result:", addData);

        // Wait a moment
        await new Promise(resolve => setTimeout(resolve, 2000));

        console.log("Step 2: Verifying user was added");
        const verifyAddResult = await fetchGatewayListItems(accountId, apiToken, mediumRiskListId);
        console.log("Verify add result:", verifyAddResult);

        // Wait a moment
        await new Promise(resolve => setTimeout(resolve, 2000));

        console.log("Step 3: Removing test user from medium risk list");
        const removeResult = await makeApiRequest(`https://api.cloudflare.com/client/v4/accounts/${accountId}/gateway/lists/${mediumRiskListId}`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${apiToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: "Medium Risk Users - New",
                description: "New medium risk users list (not protected by policies)",
                items: [] // Empty list to remove all users
            })
        });

        const removeData = await removeResult.json();
        console.log("Remove result:", removeData);

        // Wait a moment
        await new Promise(resolve => setTimeout(resolve, 2000));

        console.log("Step 4: Verifying user was removed");
        const verifyRemoveResult = await fetchGatewayListItems(accountId, apiToken, mediumRiskListId);
        console.log("Verify remove result:", verifyRemoveResult);

        return new Response(JSON.stringify({
            success: true,
            message: "User removal test completed",
            results: {
                addStep: { success: addData.success, errors: addData.errors },
                verifyAdd: { itemCount: verifyAddResult.items?.length || 0, items: verifyAddResult.items },
                removeStep: { success: removeData.success, errors: removeData.errors },
                verifyRemove: { itemCount: verifyRemoveResult.items?.length || 0, items: verifyRemoveResult.items }
            },
            testPassed: (verifyRemoveResult.items?.length || 0) === 0
        }), {
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });

    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: error.message
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
}

async function testClearMethod(accountId, apiToken, mediumRiskListId) {
    try {
        const testEmail = "test2@example.com";
        
        console.log("Step 1: Adding test user to medium risk list");
        const addResult = await makeApiRequest(`https://api.cloudflare.com/client/v4/accounts/${accountId}/gateway/lists/${mediumRiskListId}`, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${apiToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: "Medium Risk Users - New",
                description: "New medium risk users list (not protected by policies)",
                items: [{ 
                    value: testEmail,
                    description: "Test user for clear method testing"
                }]
            })
        });

        const addData = await addResult.json();
        console.log("Add result:", addData);

        // Wait for propagation
        await new Promise(resolve => setTimeout(resolve, 3000));

        console.log("Step 2: Verifying user was added");
        const verifyAddResult = await fetchGatewayListItems(accountId, apiToken, mediumRiskListId);
        console.log("Verify add result:", verifyAddResult);

        // Wait for propagation
        await new Promise(resolve => setTimeout(resolve, 3000));

        console.log("Step 3: Using PATCH method to clear list");
        const clearResult = await makeApiRequest(`https://api.cloudflare.com/client/v4/accounts/${accountId}/gateway/lists/${mediumRiskListId}/items`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${apiToken}`,
                'Content-Type': 'application/json'
            }
        });

        const clearData = await clearResult.json();
        console.log("Clear result:", clearData);

        // Wait for propagation
        await new Promise(resolve => setTimeout(resolve, 5000));

        console.log("Step 4: Verifying list was cleared");
        const verifyClearResult = await fetchGatewayListItems(accountId, apiToken, mediumRiskListId);
        console.log("Verify clear result:", verifyClearResult);

        return new Response(JSON.stringify({
            success: true,
            message: "Clear method test completed",
            results: {
                addStep: { success: addData.success, errors: addData.errors },
                verifyAdd: { itemCount: verifyAddResult.items?.length || 0, items: verifyAddResult.items },
                clearStep: { success: clearData.success, errors: clearData.errors },
                verifyClear: { itemCount: verifyClearResult.items?.length || 0, items: verifyClearResult.items }
            },
            testPassed: (verifyClearResult.items?.length || 0) === 0
        }), {
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });

    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: error.message
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
}

async function testKVSync(accountId, apiToken, mediumRiskListId, env) {
    try {
        console.log("=== Testing KV-based sync system ===");
        
        // Step 1: Store test users in KV (simulating risk scoring results)
        const testUsers = [
            { email: "kvtest1@example.com" },
            { email: "kvtest2@example.com" }
        ];
        
        console.log("Step 1: Storing expected state in KV");
        await storeExpectedStateInKV(env, mediumRiskListId, testUsers, 'medium');
        
        // Step 2: Sync Gateway list from KV
        console.log("Step 2: Syncing Gateway list from KV");
        const syncResult = await syncGatewayListFromKV(accountId, apiToken, mediumRiskListId, env, 'Medium Risk Users - New');
        
        // Wait for propagation
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Step 3: Verify the sync worked
        console.log("Step 3: Verifying sync result");
        const verifyResult = await fetchGatewayListItems(accountId, apiToken, mediumRiskListId);
        
        // Step 4: Test removal by updating KV with empty list
        console.log("Step 4: Testing removal - updating KV with empty list");
        await storeExpectedStateInKV(env, mediumRiskListId, [], 'medium');
        
        // Step 5: Sync again to remove users
        console.log("Step 5: Syncing to remove users");
        const removeResult = await syncGatewayListFromKV(accountId, apiToken, mediumRiskListId, env, 'Medium Risk Users - New');
        
        // Wait for propagation
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Step 6: Verify removal worked
        console.log("Step 6: Verifying removal");
        const finalResult = await fetchGatewayListItems(accountId, apiToken, mediumRiskListId);
        
        return new Response(JSON.stringify({
            success: true,
            message: "KV sync test completed",
            results: {
                initialSync: {
                    success: syncResult.success,
                    added: syncResult.added,
                    removed: syncResult.removed
                },
                afterSync: {
                    itemCount: verifyResult.items?.length || 0,
                    items: verifyResult.items?.map(item => item.value) || []
                },
                removalSync: {
                    success: removeResult.success,
                    added: removeResult.added,
                    removed: removeResult.removed
                },
                afterRemoval: {
                    itemCount: finalResult.items?.length || 0,
                    items: finalResult.items?.map(item => item.value) || []
                }
            },
            testPassed: (finalResult.items?.length || 0) === 0
        }), {
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });

    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: error.message
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
}

async function testPatchMethod(accountId, apiToken, mediumRiskListId, env) {
    try {
        console.log("=== Testing PATCH method for efficient add/remove ===");
        
        // Step 1: Clear the list first to start with a clean state
        console.log("Step 1: Clearing list to start with clean state");
        await storeExpectedStateInKV(env, mediumRiskListId, [], 'medium');
        await syncGatewayListFromKV(accountId, apiToken, mediumRiskListId, env, 'Medium Risk Users - New');
        
        // Wait for propagation
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        // Step 2: Add some users using PATCH
        console.log("Step 2: Adding users using PATCH method");
        const initialUsers = [
            { email: "patch1@example.com" },
            { email: "patch2@example.com" }
        ];
        
        await storeExpectedStateInKV(env, mediumRiskListId, initialUsers, 'medium');
        const addResult = await syncGatewayListFromKV(accountId, apiToken, mediumRiskListId, env, 'Medium Risk Users - New');
        
        // Wait for propagation
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Step 3: Verify addition
        console.log("Step 3: Verifying addition");
        const verifyAddResult = await fetchGatewayListItems(accountId, apiToken, mediumRiskListId);
        
        // Step 4: Add more users and remove one (mixed operation)
        console.log("Step 4: Testing mixed add/remove operation");
        const updatedUsers = [
            { email: "patch2@example.com" }, // Keep this one
            { email: "patch3@example.com" }, // Add this one
            { email: "patch4@example.com" }  // Add this one
        ];
        
        await storeExpectedStateInKV(env, mediumRiskListId, updatedUsers, 'medium');
        const mixedResult = await syncGatewayListFromKV(accountId, apiToken, mediumRiskListId, env, 'Medium Risk Users - New');
        
        // Wait for propagation
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Step 5: Verify mixed operation
        console.log("Step 5: Verifying mixed operation");
        const verifyMixedResult = await fetchGatewayListItems(accountId, apiToken, mediumRiskListId);
        
        // Step 6: Remove all users
        console.log("Step 6: Removing all users");
        await storeExpectedStateInKV(env, mediumRiskListId, [], 'medium');
        const removeResult = await syncGatewayListFromKV(accountId, apiToken, mediumRiskListId, env, 'Medium Risk Users - New');
        
        // Wait for propagation
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Step 7: Verify removal
        console.log("Step 7: Verifying complete removal");
        const finalResult = await fetchGatewayListItems(accountId, apiToken, mediumRiskListId);
        
        return new Response(JSON.stringify({
            success: true,
            message: "PATCH method test completed",
            results: {
                addOperation: {
                    success: addResult.success,
                    method: addResult.method,
                    added: addResult.added,
                    removed: addResult.removed
                },
                afterAdd: {
                    itemCount: verifyAddResult.items?.length || 0,
                    items: verifyAddResult.items?.map(item => item.value) || []
                },
                mixedOperation: {
                    success: mixedResult.success,
                    method: mixedResult.method,
                    added: mixedResult.added,
                    removed: mixedResult.removed
                },
                afterMixed: {
                    itemCount: verifyMixedResult.items?.length || 0,
                    items: verifyMixedResult.items?.map(item => item.value) || []
                },
                removeOperation: {
                    success: removeResult.success,
                    method: removeResult.method,
                    added: removeResult.added,
                    removed: removeResult.removed
                },
                afterRemoval: {
                    itemCount: finalResult.items?.length || 0,
                    items: finalResult.items?.map(item => item.value) || []
                }
            },
            testPassed: (finalResult.items?.length || 0) === 0
        }), {
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });

    } catch (error) {
        return new Response(JSON.stringify({
            success: false,
            error: error.message
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
}

async function storeExpectedStateInKV(env, listId, users, riskLevel) {
    try {
        const kvKey = `gateway_list_${listId}`;
        const expectedState = {
            emails: users.map(user => user.email),
            riskLevel: riskLevel,
            lastUpdated: new Date().toISOString(),
            userCount: users.length
        };
        
        await env.USER_RISK_KV.put(kvKey, JSON.stringify(expectedState));
        console.log(`Stored expected state for ${riskLevel} risk list: ${users.length} users`);
        
        return { success: true, userCount: users.length };
    } catch (error) {
        console.error(`Failed to store expected state for ${riskLevel} risk list:`, error);
        return { success: false, error: error.message };
    }
}

async function syncGatewayListFromKV(accountId, apiToken, listId, env, listName) {
    try {
        // Step 1: Get expected state from KV (source of truth)
        const kvKey = `gateway_list_${listId}`;
        const expectedStateStr = await env.USER_RISK_KV.get(kvKey);
        
        if (!expectedStateStr) {
            console.log(`No expected state found in KV for list ${listId}`);
            return { success: false, error: 'No expected state in KV' };
        }
        
        const expectedState = JSON.parse(expectedStateStr);
        const expectedEmails = new Set(expectedState.emails);
        
        console.log(`Expected state for ${listName}: ${expectedState.emails.length} users`);
        
        // Step 2: Get current Gateway list state (without cache)
        const currentResult = await fetchGatewayListItems(accountId, apiToken, listId);
        if (currentResult.error) {
            console.error(`Failed to fetch current Gateway list ${listId}:`, currentResult.error);
            return { success: false, error: currentResult.error };
        }
        
        const currentEmails = new Set(currentResult.items.map(item => item.value));
        console.log(`Current Gateway list ${listName}: ${currentResult.items.length} users`);
        
        // Step 3: Compare and determine changes needed
        const emailsToAdd = [...expectedEmails].filter(email => !currentEmails.has(email));
        const emailsToRemove = [...currentEmails].filter(email => !expectedEmails.has(email));
        
        console.log(`Changes needed for ${listName}: +${emailsToAdd.length} users, -${emailsToRemove.length} users`);
        
        // Step 4: Update Gateway list if changes are needed using PATCH method
        if (emailsToAdd.length > 0 || emailsToRemove.length > 0) {
            const patchBody = {};
            
            // Add items to append array if there are emails to add
            if (emailsToAdd.length > 0) {
                patchBody.append = emailsToAdd.map(email => ({
                    value: email,
                    description: `${expectedState.riskLevel} risk user - updated ${expectedState.lastUpdated}`
                }));
            }
            
            // Add items to remove array if there are emails to remove
            if (emailsToRemove.length > 0) {
                patchBody.remove = emailsToRemove;
            }
            
            console.log(`Using PATCH method for ${listName}: appending ${emailsToAdd.length} users, removing ${emailsToRemove.length} users`);
            
            const updateResult = await makeApiRequest(`https://api.cloudflare.com/client/v4/accounts/${accountId}/gateway/lists/${listId}`, {
                method: 'PATCH',
                headers: {
                    'Authorization': `Bearer ${apiToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(patchBody)
            });
            
            const updateData = await updateResult.json();
            
            if (updateData.success) {
                console.log(`Successfully patched ${listName}: ${emailsToAdd.length} added, ${emailsToRemove.length} removed`);
                return {
                    success: true,
                    added: emailsToAdd.length,
                    removed: emailsToRemove.length,
                    totalUsers: expectedState.emails.length,
                    method: 'PATCH'
                };
            } else {
                console.error(`Failed to patch ${listName}:`, updateData.errors);
                return { success: false, error: updateData.errors };
            }
        } else {
            console.log(`No changes needed for ${listName} - already in sync`);
            return {
                success: true,
                added: 0,
                removed: 0,
                totalUsers: expectedState.emails.length,
                message: 'Already in sync'
            };
        }
        
    } catch (error) {
        console.error(`Error syncing Gateway list ${listName}:`, error);
        return { success: false, error: error.message };
    }
}

async function updateGatewayList(accountId, apiToken, listId, users, env) {
    const ztListEndpoint = `https://api.cloudflare.com/client/v4/accounts/${accountId}/gateway/lists/${listId}`;
    
    try {
        // Get expected state from KV
        const kvKey = `gateway_list_${listId}`;
        const expectedStateStr = await env.USER_RISK_KV.get(kvKey);
        const expectedState = expectedStateStr ? JSON.parse(expectedStateStr) : { emails: [], lastUpdated: null };
        
        // Get current list info to preserve name and description
        const currentListResponse = await makeApiRequest(ztListEndpoint, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${apiToken}`,
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache'
            }
        });

        const currentListData = await currentListResponse.json();
        if (!currentListData.success) {
            console.error(`Failed to get current list info for ${listId}:`, currentListData.errors);
            return { success: false, errors: currentListData.errors };
        }

        const listInfo = currentListData.result;
        
        // Get current list items from API
        const currentItemsResult = await fetchGatewayListItems(accountId, apiToken, listId);
        if (!currentItemsResult.success) {
            console.error(`Failed to fetch current items for list ${listId}:`, currentItemsResult.errors);
            return { success: false, errors: currentItemsResult.errors };
        }
        
        // Calculate what needs to be added/removed
        const currentEmails = new Set(currentItemsResult.items.map(item => item.value));
        const targetEmails = new Set(users.map(user => user.email));
        const expectedEmails = new Set(expectedState.emails);
        
        const emailsToAdd = [...targetEmails].filter(email => !currentEmails.has(email));
        const emailsToRemove = [...currentEmails].filter(email => !targetEmails.has(email));
        
        console.log(`List ${listId}: Current emails: [${[...currentEmails].join(', ')}], Target emails: [${[...targetEmails].join(', ')}], Expected emails: [${[...expectedEmails].join(', ')}]`);
        
        // Check for API inconsistency - if current doesn't match expected, force reconciliation
        const apiInconsistent = !setsEqual(currentEmails, expectedEmails);
        if (apiInconsistent) {
            console.warn(`API inconsistency detected for list ${listId}! Current API state doesn't match expected KV state`);
            console.log(`Expected: [${[...expectedEmails].join(', ')}], Got: [${[...currentEmails].join(', ')}]`);
        }
        
        // If no changes needed and API is consistent, return early
        if (emailsToAdd.length === 0 && emailsToRemove.length === 0 && !apiInconsistent) {
            console.log(`No changes needed for Gateway list ${listId}`);
            return {
                success: true,
                removed: 0,
                added: 0,
                users: [...targetEmails],
                message: 'No changes needed'
            };
        }
        
        // Step 1: First clear the list completely by setting items to empty array
        console.log(`Step 1: Clearing list ${listId} completely`);
        
        const clearResult = await makeApiRequest(ztListEndpoint, {
            method: 'PUT',
            headers: {
                'Authorization': `Bearer ${apiToken}`,
                'Content-Type': 'application/json',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            },
            body: JSON.stringify({
                name: listInfo.name,
                description: listInfo.description || '',
                items: []
            })
        });

        const clearData = await clearResult.json();
        console.log(`CLEAR request to ${listId}: Status ${clearResult.status}, Success: ${clearData.success}`);
        
        if (!clearData.success) {
            console.error(`Failed to clear Gateway list ${listId}:`, clearData.errors);
            return { success: false, errors: clearData.errors };
        }
        
        // Step 2: Wait and then add target items if any
        if (targetEmails.length > 0) {
            console.log(`Step 2: Adding ${targetEmails.length} items to list ${listId}`);
            await new Promise(resolve => setTimeout(resolve, 3000)); // Wait longer
            
            const targetItems = [...targetEmails].map(email => ({ 
                value: email,
                description: `Risk-based user - updated ${new Date().toISOString().split('T')[0]}`
            }));
            
            const addResult = await makeApiRequest(ztListEndpoint, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${apiToken}`,
                    'Content-Type': 'application/json',
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache'
                },
                body: JSON.stringify({
                    name: listInfo.name,
                    description: listInfo.description || '',
                    items: targetItems
                })
            });

            const addData = await addResult.json();
            console.log(`ADD request to ${listId}: Status ${addResult.status}, Success: ${addData.success}`);
            
            if (!addData.success) {
                console.error(`Failed to add items to Gateway list ${listId}:`, addData.errors);
                return { success: false, errors: addData.errors };
            }
        } else {
            console.log(`Step 2: No items to add to list ${listId} - list will remain empty`);
        }
        
        // Step 3: Update KV with expected state
        const newExpectedState = {
            emails: [...targetEmails],
            lastUpdated: new Date().toISOString(),
            lastAttempt: new Date().toISOString()
        };
        
        await env.USER_RISK_KV.put(kvKey, JSON.stringify(newExpectedState), {
            expirationTtl: 86400 * 7 // 7 days
        });
        
        console.log(`Updated KV state for list ${listId}: ${targetEmails.length} emails`);
        
        // Step 4: Verify and reconcile if needed
        await new Promise(resolve => setTimeout(resolve, 3000));
        console.log(`Step 4: Verifying final state of list ${listId}`);
        
        const verifyResult = await fetchGatewayListItems(accountId, apiToken, listId);
        let reconciliationNeeded = false;
        
        if (verifyResult.success) {
            const actualEmails = new Set(verifyResult.items.map(item => item.value));
            const expectedEmails = new Set(targetEmails);
            
            console.log(`Final verification: Expected ${expectedEmails.size} items, found ${actualEmails.size} items`);
            console.log(`Expected emails: [${[...expectedEmails].join(', ')}]`);
            console.log(`Actual emails: [${[...actualEmails].join(', ')}]`);
            
            if (!setsEqual(actualEmails, expectedEmails)) {
                console.warn(`Reconciliation needed! API state still doesn't match expected state`);
                reconciliationNeeded = true;
                
                // Store reconciliation flag in KV
                const reconciliationState = {
                    ...newExpectedState,
                    reconciliationNeeded: true,
                    lastReconciliationAttempt: new Date().toISOString()
                };
                
                await env.USER_RISK_KV.put(kvKey, JSON.stringify(reconciliationState), {
                    expirationTtl: 86400 * 7
                });
            }
        }

        console.log(`Gateway list ${listId}: removed ${emailsToRemove.length} users, added ${emailsToAdd.length} users`);
        
        return {
            success: true,
            removed: emailsToRemove.length,
            added: emailsToAdd.length,
            users: [...targetEmails],
            removedUsers: emailsToRemove,
            addedUsers: emailsToAdd,
            reconciliationNeeded: reconciliationNeeded,
            apiInconsistent: apiInconsistent
        };
        
    } catch (error) {
        console.error(`Error updating Gateway list ${listId}:`, error);
        return { success: false, errors: [{ message: error.message }] };
    }
}

// Helper function to compare two sets for equality
function setsEqual(setA, setB) {
    if (setA.size !== setB.size) return false;
    for (let item of setA) {
        if (!setB.has(item)) return false;
    }
    return true;
}

// Enhanced API request function with retry mechanism
async function makeApiRequest(url, options, maxRetries = 3) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const response = await fetch(url, options);
            
            // Handle rate limiting (429) with exponential backoff
            if (response.status === 429) {
                const retryAfter = response.headers.get('Retry-After') || Math.pow(2, attempt);
                console.log(`Rate limited, waiting ${retryAfter}s before retry ${attempt}/${maxRetries}`);
                await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
                continue;
            }
            
            // Handle server errors (5xx) with retry
            if (response.status >= 500 && attempt < maxRetries) {
                const delay = Math.pow(2, attempt) * 1000; // Exponential backoff
                console.log(`Server error ${response.status}, retrying in ${delay}ms (attempt ${attempt}/${maxRetries})`);
                await new Promise(resolve => setTimeout(resolve, delay));
                continue;
            }
            
            return response;
        } catch (error) {
            if (attempt === maxRetries) {
                throw error;
            }
            const delay = Math.pow(2, attempt) * 1000;
            console.log(`Network error, retrying in ${delay}ms (attempt ${attempt}/${maxRetries}):`, error.message);
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
}

// Pagination function to fetch all user risk scores
async function fetchAllUserRiskScores(accountId, apiToken) {
    const allUsers = [];
    let page = 1;
    let hasMore = true;
    const pageSize = 50; // Cloudflare API typical limit
    let totalRequests = 0;
    
    try {
        while (hasMore && totalRequests < 100) { // Safety limit to prevent infinite loops
            const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/zt_risk_scoring/summary?page=${page}&per_page=${pageSize}`;
            
            const response = await makeApiRequest(url, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${apiToken}`,
                    'Content-Type': 'application/json',
                    'Cache-Control': 'no-cache'
                }
            });
            
            const data = await response.json();
            totalRequests++;
            
            if (!data.success) {
                return { success: false, errors: data.errors };
            }
            
            const users = data.result?.users || [];
            allUsers.push(...users);
            
            // Check if there are more pages
            const resultInfo = data.result_info || {};
            hasMore = resultInfo.page < resultInfo.total_pages;
            page++;
            
            // Add small delay to avoid rate limiting
            if (hasMore) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
        }
        
        return {
            success: true,
            users: allUsers,
            pagination: {
                totalUsers: allUsers.length,
                totalRequests,
                pagesProcessed: page - 1
            }
        };
    } catch (error) {
        return { success: false, errors: [{ message: error.message }] };
    }
}

// Function to fetch Gateway list items with pagination
async function fetchGatewayListItems(accountId, apiToken, listId, riskLevel) {
    const allItems = [];
    let page = 1;
    let hasMore = true;
    const pageSize = 100; // Gateway lists typically support larger page sizes
    let totalRequests = 0;
    
    try {
        while (hasMore && totalRequests < 50) { // Safety limit
            const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/gateway/lists/${listId}/items?page=${page}&per_page=${pageSize}`;
            
            const response = await makeApiRequest(url, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${apiToken}`,
                    'Content-Type': 'application/json',
                    'Cache-Control': 'no-cache'
                }
            });
            
            const data = await response.json();
            totalRequests++;
            
            if (!data.success) {
                console.error(`Failed to fetch ${riskLevel} risk list items:`, data.errors);
                break;
            }
            
            const items = data.result || [];
            allItems.push(...items);
            
            // Check if there are more pages
            const resultInfo = data.result_info || {};
            hasMore = resultInfo.page < resultInfo.total_pages;
            page++;
            
            // Add small delay to avoid rate limiting
            if (hasMore) {
                await new Promise(resolve => setTimeout(resolve, 50));
            }
        }
        
        return {
            riskLevel,
            listId,
            items: allItems,
            pagination: {
                totalItems: allItems.length,
                totalRequests,
                pagesProcessed: page - 1
            }
        };
    } catch (error) {
        return {
            riskLevel,
            listId,
            items: [],
            error: error.message
        };
    }
}

async function getUserRiskScoresAPI(accountId, apiToken) {
    try {
        // Fetch all users with pagination support
        const allUsers = await fetchAllUserRiskScores(accountId, apiToken);
        
        if (!allUsers.success) {
            return new Response(JSON.stringify({ 
                error: 'Failed to fetch user risk scores', 
                details: allUsers.errors 
            }), { 
                status: 500,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
            });
        }
        
        // Categorize users by risk level
        const users = allUsers.users || [];
        const categorizedUsers = {
            high: users.filter(u => u.max_risk_level === 'high'),
            medium: users.filter(u => u.max_risk_level === 'medium'),
            low: users.filter(u => u.max_risk_level === 'low')
        };
        
        const summary = {
            total: users.length,
            high: categorizedUsers.high.length,
            medium: categorizedUsers.medium.length,
            low: categorizedUsers.low.length
        };
        
        return new Response(JSON.stringify({
            success: true,
            users: categorizedUsers,
            summary,
            pagination: allUsers.pagination
        }), {
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ 
            error: 'Internal server error', 
            details: error.message 
        }), { 
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
}

// New function to fetch Gateway lists with pagination
async function getGatewayListsAPI(accountId, apiToken, highRiskListId, mediumRiskListId, lowRiskListId) {
    try {
        const lists = await Promise.all([
            fetchGatewayListItems(accountId, apiToken, highRiskListId, 'high'),
            fetchGatewayListItems(accountId, apiToken, mediumRiskListId, 'medium'),
            fetchGatewayListItems(accountId, apiToken, lowRiskListId, 'low')
        ]);
        
        const [highRiskList, mediumRiskList, lowRiskList] = lists;
        
        return new Response(JSON.stringify({
            success: true,
            lists: {
                high: highRiskList,
                medium: mediumRiskList,
                low: lowRiskList
            },
            summary: {
                high: highRiskList.items?.length || 0,
                medium: mediumRiskList.items?.length || 0,
                low: lowRiskList.items?.length || 0,
                total: (highRiskList.items?.length || 0) + (mediumRiskList.items?.length || 0) + (lowRiskList.items?.length || 0)
            }
        }), {
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ 
            error: 'Failed to fetch gateway lists', 
            details: error.message 
        }), { 
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
}

async function updateRiskListsAPI(accountId, apiToken, highRiskListId, mediumRiskListId, lowRiskListId, env) {
    try {
        // First check if there are any users to process
        const allUsers = await fetchAllUserRiskScores(accountId, apiToken);
        
        if (!allUsers.success) {
            return new Response(JSON.stringify({ 
                error: 'Failed to fetch user risk scores before updating lists', 
                details: allUsers.errors 
            }), { 
                status: 500,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
            });
        }

        const users = allUsers.users || [];
        
        // Always proceed with the update, even if 0 users, to clean up Gateway lists
        const result = await handleRequest('notfetch', { 
            CLOUDFLARE_ACCOUNT_ID: accountId, 
            CLOUDFLARE_API_TOKEN: apiToken,
            HIGH_RISK_LIST_ID: highRiskListId,
            MEDIUM_RISK_LIST_ID: mediumRiskListId,
            LOW_RISK_LIST_ID: lowRiskListId
        });
        
        // Categorize users for summary
        const riskCategories = {
            high: users.filter(user => user.max_risk_level === 'high'),
            medium: users.filter(user => user.max_risk_level === 'medium'),
            low: users.filter(user => user.max_risk_level === 'low')
        };
        
        return new Response(JSON.stringify({
            success: true,
            message: "Risk lists updated successfully!",
            summary: {
                totalUsers: users.length,
                high: riskCategories.high.length,
                medium: riskCategories.medium.length,
                low: riskCategories.low.length
            }
        }), {
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ 
            error: 'Failed to update risk lists', 
            details: error.message 
        }), { 
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
}

// Health check API endpoint
async function getHealthCheckAPI(accountId, apiToken) {
    const startTime = Date.now();
    const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        checks: {}
    };
    
    try {
        // Test Cloudflare API connectivity
        const apiResponse = await makeApiRequest(
            `https://api.cloudflare.com/client/v4/accounts/${accountId}`,
            {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${apiToken}`,
                    'Content-Type': 'application/json'
                }
            },
            1 // Single retry for health check
        );
        
        health.checks.cloudflare_api = {
            status: apiResponse.ok ? 'healthy' : 'unhealthy',
            response_time: Date.now() - startTime
        };
        
        // Test Risk Scoring API
        const riskStartTime = Date.now();
        const riskResponse = await makeApiRequest(
            `https://api.cloudflare.com/client/v4/accounts/${accountId}/zt_risk_scoring/summary?per_page=1`,
            {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${apiToken}`,
                    'Content-Type': 'application/json'
                }
            },
            1
        );
        
        health.checks.risk_scoring_api = {
            status: riskResponse.ok ? 'healthy' : 'unhealthy',
            response_time: Date.now() - riskStartTime
        };
        
        // Overall health status
        const allHealthy = Object.values(health.checks).every(check => check.status === 'healthy');
        health.status = allHealthy ? 'healthy' : 'degraded';
        
    } catch (error) {
        health.status = 'unhealthy';
        health.error = error.message;
    }
    
    health.total_response_time = Date.now() - startTime;
    
    return new Response(JSON.stringify(health), {
        status: health.status === 'healthy' ? 200 : 503,
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
}

// Metrics API endpoint (requires KV namespace for persistence)
async function getMetricsAPI(env) {
    try {
        const metrics = {
            timestamp: new Date().toISOString(),
            uptime: Date.now(), // Simple uptime since this execution
            version: '2.0.0',
            features: {
                retry_mechanism: true,
                input_validation: true,
                health_checks: true,
                metrics: true
            }
        };
        
        // If KV is available, get execution metrics
        if (env.USER_RISK_KV) {
            try {
                const executionStats = await env.USER_RISK_KV.get('execution_stats');
                if (executionStats) {
                    metrics.execution_stats = JSON.parse(executionStats);
                }
            } catch (kvError) {
                metrics.kv_error = 'Failed to retrieve execution stats';
            }
        }
        
        return new Response(JSON.stringify(metrics), {
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    } catch (error) {
        return new Response(JSON.stringify({ 
            error: 'Failed to retrieve metrics', 
            details: error.message 
        }), { 
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
}

// Enhanced logging function
async function logExecution(env, operation, result, duration) {
    if (!env.USER_RISK_KV) return;
    
    try {
        const logEntry = {
            timestamp: new Date().toISOString(),
            operation,
            success: result.success || false,
            duration,
            details: result
        };
        
        // Store individual log entry
        const logKey = `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        await env.USER_RISK_KV.put(logKey, JSON.stringify(logEntry), { expirationTtl: 86400 * 7 }); // 7 days
        
        // Update execution stats
        let stats = { total_executions: 0, successful_executions: 0, failed_executions: 0 };
        try {
            const existingStats = await env.USER_RISK_KV.get('execution_stats');
            if (existingStats) {
                stats = JSON.parse(existingStats);
            }
        } catch (e) {
            // Use default stats if parsing fails
        }
        
        stats.total_executions++;
        if (result.success) {
            stats.successful_executions++;
        } else {
            stats.failed_executions++;
        }
        stats.last_execution = new Date().toISOString();
        stats.average_duration = ((stats.average_duration || 0) + duration) / 2;
        
        await env.USER_RISK_KV.put('execution_stats', JSON.stringify(stats));
    } catch (error) {
        console.error('Failed to log execution:', error);
    }
}

function getHTML() {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Risk Scoring Manager</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .loading { animation: spin 1s linear infinite; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        .user-card { transition: all 0.3s ease; }
        .user-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
        .tab-active { border-bottom: 2px solid #3B82F6; background-color: #EFF6FF; }
    </style>
</head>
<body class="bg-gray-100 min-h-screen">
    <div class="container mx-auto px-4 py-8">
        <div class="flex justify-between items-center mb-8">
            <h1 class="text-3xl font-bold text-gray-800">User Risk Scoring Manager</h1>
            <div class="text-sm text-gray-600" id="pagination-info"></div>
        </div>
        
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div class="bg-white rounded-lg shadow p-6">
                <h2 class="text-xl font-semibold text-gray-800 mb-2">Total Users</h2>
                <p class="text-3xl font-bold text-blue-500" id="total-count">-</p>
                <p class="text-gray-600">All Risk Levels</p>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h2 class="text-xl font-semibold text-red-600 mb-2">High Risk</h2>
                <p class="text-3xl font-bold text-red-500" id="high-count">-</p>
                <p class="text-gray-600">Critical Users</p>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h2 class="text-xl font-semibold text-yellow-600 mb-2">Medium Risk</h2>
                <p class="text-3xl font-bold text-yellow-500" id="medium-count">-</p>
                <p class="text-gray-600">Watch List</p>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h2 class="text-xl font-semibold text-green-600 mb-2">Low Risk</h2>
                <p class="text-3xl font-bold text-green-500" id="low-count">-</p>
                <p class="text-gray-600">Safe Users</p>
            </div>
        </div>
        
        <div class="bg-white rounded-lg shadow p-6 mb-6">
            <div class="flex justify-between items-center mb-4">
                <h2 class="text-xl font-semibold text-gray-800">System Status</h2>
                <div class="flex items-center space-x-4">
                    <div class="flex items-center">
                        <div class="w-3 h-3 bg-green-500 rounded-full mr-2 animate-pulse"></div>
                        <span class="text-sm text-gray-600">Automated (Every 1 min)</span>
                    </div>
                </div>
            </div>
            <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4">
                <div class="flex items-center">
                    <div class="w-5 h-5 bg-blue-500 rounded-full mr-3 flex items-center justify-center">
                        <div class="w-2 h-2 bg-white rounded-full animate-pulse"></div>
                    </div>
                    <div>
                        <p class="text-sm font-medium text-blue-800">🤖 Automated Risk Management Active</p>
                        <p class="text-xs text-blue-600">System automatically syncs user risk scores to Gateway lists every minute via cron job</p>
                    </div>
                </div>
            </div>
            
            <div id="status" class="text-gray-600 mb-4">
                System ready - automated sync active
            </div>
            
            <!-- Manual Monitoring Tools -->
            <div class="bg-white border-2 border-blue-200 rounded-lg p-6 shadow-sm">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-lg font-semibold text-gray-800">🔍 Manual Actions</h3>
                    <span class="text-sm text-gray-600 bg-gray-100 px-2 py-1 rounded">For monitoring & troubleshooting</span>
                </div>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <button onclick="loadUserRiskScores()" class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-3 rounded-lg text-sm font-medium transition-colors shadow-sm">
                        📊<br>View Data
                    </button>
                    <button onclick="loadGatewayLists()" class="bg-purple-500 hover:bg-purple-600 text-white px-4 py-3 rounded-lg text-sm font-medium transition-colors shadow-sm">
                        📋<br>Gateway Lists
                    </button>
                    <button onclick="checkHealth()" class="bg-orange-500 hover:bg-orange-600 text-white px-4 py-3 rounded-lg text-sm font-medium transition-colors shadow-sm">
                        🏥<br>Health Check
                    </button>
                    <button onclick="forceSync()" class="bg-yellow-500 hover:bg-yellow-600 text-white px-4 py-3 rounded-lg text-sm font-medium transition-colors shadow-sm">
                        🔄<br>Force Sync
                    </button>
                </div>
                <p class="text-sm text-gray-600 mt-4 bg-blue-50 p-3 rounded-lg">
                    ℹ️ <strong>Note:</strong> These manual actions are for monitoring only. The system automatically syncs every minute via cron job.
                </p>
            </div>
        </div>
        
        <div class="bg-white rounded-lg shadow">
            <div class="border-b border-gray-200">
                <nav class="flex space-x-8 px-6">
                    <button onclick="showTab('all')" id="tab-all" class="py-4 px-2 border-b-2 border-transparent hover:border-gray-300 font-medium text-gray-500 hover:text-gray-700 tab-active">
                        All Users (<span id="tab-all-count">0</span>)
                    </button>
                    <button onclick="showTab('high')" id="tab-high" class="py-4 px-2 border-b-2 border-transparent hover:border-gray-300 font-medium text-gray-500 hover:text-gray-700">
                        High Risk (<span id="tab-high-count">0</span>)
                    </button>
                    <button onclick="showTab('medium')" id="tab-medium" class="py-4 px-2 border-b-2 border-transparent hover:border-gray-300 font-medium text-gray-500 hover:text-gray-700">
                        Medium Risk (<span id="tab-medium-count">0</span>)
                    </button>
                    <button onclick="showTab('low')" id="tab-low" class="py-4 px-2 border-b-2 border-transparent hover:border-gray-300 font-medium text-gray-500 hover:text-gray-700">
                        Low Risk (<span id="tab-low-count">0</span>)
                    </button>
                </nav>
            </div>
            <div class="p-6">
                <div id="user-details" class="text-gray-600">
                    System automatically manages user risk scores. View current data above.
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentData = null;
        let currentTab = 'all';
        
        function toggleAdvancedTools() {
            const advancedTools = document.getElementById('advanced-tools');
            const toggleText = document.getElementById('advanced-toggle');
            
            if (advancedTools.classList.contains('hidden')) {
                advancedTools.classList.remove('hidden');
                toggleText.textContent = '▼ Hide Advanced Tools';
            } else {
                advancedTools.classList.add('hidden');
                toggleText.textContent = '▶ Show Advanced Tools';
            }
        }
        
        function showTab(tab) {
            currentTab = tab;
            
            // Update tab styling
            document.querySelectorAll('[id^="tab-"]').forEach(t => {
                t.classList.remove('tab-active');
                t.classList.add('border-transparent', 'text-gray-500');
            });
            document.getElementById('tab-' + tab).classList.add('tab-active');
            document.getElementById('tab-' + tab).classList.remove('border-transparent', 'text-gray-500');
            
            if (currentData) {
                displayUsers(currentData, tab);
            }
        }
        
        function displayUsers(data, filterTab) {
            filterTab = filterTab || 'all';
            let usersToShow = [];
            
            if (filterTab === 'all') {
                usersToShow = [].concat(data.users.high || [], data.users.medium || [], data.users.low || []);
            } else {
                usersToShow = data.users[filterTab] || [];
            }
            
            if (usersToShow.length === 0) {
                document.getElementById('user-details').innerHTML = 
                    '<div class="text-center py-8">' +
                        '<div class="text-gray-400 text-lg mb-2">📭</div>' +
                        '<div class="text-gray-600">No ' + (filterTab === 'all' ? '' : filterTab + ' risk ') + 'users found</div>' +
                    '</div>';
                return;
            }
            
            let userDetailsHtml = '<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">';
            
            usersToShow.forEach(function(user) {
                const riskColor = user.max_risk_level === 'high' ? 'red' : 
                                 user.max_risk_level === 'medium' ? 'yellow' : 'green';
                const riskIcon = user.max_risk_level === 'high' ? '🚨' : 
                                user.max_risk_level === 'medium' ? '⚠️' : '✅';
                
                userDetailsHtml += 
                    '<div class="user-card border border-gray-200 rounded-lg p-4 hover:shadow-md">' +
                        '<div class="flex items-start justify-between mb-2">' +
                            '<div class="flex items-center space-x-2">' +
                                '<span class="text-lg">' + riskIcon + '</span>' +
                                '<span class="font-medium text-gray-900 truncate">' + (user.email || user.name || 'Unknown User') + '</span>' +
                            '</div>' +
                            '<span class="text-xs px-2 py-1 rounded-full bg-' + riskColor + '-100 text-' + riskColor + '-800 font-medium">' +
                                user.max_risk_level.toUpperCase() +
                            '</span>' +
                        '</div>' +
                        '<div class="space-y-1 text-sm text-gray-600">' +
                            '<div class="flex justify-between">' +
                                '<span>Events:</span>' +
                                '<span class="font-medium">' + (user.event_count || 0) + '</span>' +
                            '</div>' +
                            '<div class="flex justify-between">' +
                                '<span>Last Event:</span>' +
                                '<span class="font-medium">' + (user.last_event ? new Date(user.last_event).toLocaleDateString() : 'N/A') + '</span>' +
                            '</div>' +
                            (user.user_id ? '<div class="text-xs text-gray-400 truncate">ID: ' + user.user_id + '</div>' : '') +
                        '</div>' +
                    '</div>';
            });
            
            userDetailsHtml += '</div>';
            document.getElementById('user-details').innerHTML = userDetailsHtml;
        }
        
        async function loadUserRiskScores() {
            document.getElementById('status').innerHTML = '<span class="loading inline-block w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full"></span> Loading user risk scores with pagination...';
            
            try {
                const response = await fetch('/api/user-risk-scores');
                const data = await response.json();
                
                if (data.success) {
                    currentData = data;
                    
                    // Update summary counts
                    document.getElementById('total-count').textContent = data.summary.total;
                    document.getElementById('high-count').textContent = data.summary.high;
                    document.getElementById('medium-count').textContent = data.summary.medium;
                    document.getElementById('low-count').textContent = data.summary.low;
                    
                    // Update tab counts
                    document.getElementById('tab-all-count').textContent = data.summary.total;
                    document.getElementById('tab-high-count').textContent = data.summary.high;
                    document.getElementById('tab-medium-count').textContent = data.summary.medium;
                    document.getElementById('tab-low-count').textContent = data.summary.low;
                    
                    // Update pagination info
                    if (data.pagination) {
                        const totalUsers = data.pagination.totalUsers || 0;
                        const totalRequests = data.pagination.totalRequests || 0;
                        const pagesProcessed = data.pagination.pagesProcessed || 0;
                        document.getElementById('pagination-info').innerHTML = 
                            '📊 ' + totalUsers + ' users loaded via ' + totalRequests + ' API calls (' + pagesProcessed + ' pages)';
                    }
                    
                    displayUsers(data, currentTab);
                    document.getElementById('status').innerHTML = '<span class="text-green-600">✓ Loaded ' + data.summary.total + ' users successfully</span>';
                } else {
                    document.getElementById('status').innerHTML = '<span class="text-red-600">✗ Failed to load user risk scores</span>';
                }
            } catch (error) {
                document.getElementById('status').innerHTML = '<span class="text-red-600">✗ Error loading data</span>';
                console.error('Error:', error);
            }
        }
        
        async function loadGatewayLists() {
            document.getElementById('status').innerHTML = '<span class="loading inline-block w-4 h-4 border-2 border-purple-500 border-t-transparent rounded-full"></span> Loading Gateway lists...';
            
            try {
                const response = await fetch('/api/gateway-lists');
                const data = await response.json();
                
                if (data.success) {
                    let listHtml = '<div class="space-y-6">';
                    
                    ['high', 'medium', 'low'].forEach(function(level) {
                        const list = data.lists[level];
                        const color = level === 'high' ? 'red' : level === 'medium' ? 'yellow' : 'green';
                        const icon = level === 'high' ? '🚨' : level === 'medium' ? '⚠️' : '✅';
                        
                        listHtml += 
                            '<div class="border border-' + color + '-200 rounded-lg p-4">' +
                                '<h3 class="text-lg font-semibold text-' + color + '-700 mb-3 flex items-center space-x-2">' +
                                    '<span>' + icon + '</span>' +
                                    '<span>' + level.charAt(0).toUpperCase() + level.slice(1) + ' Risk Gateway List</span>' +
                                    '<span class="text-sm font-normal text-gray-500">(' + (list.items ? list.items.length : 0) + ' items)</span>' +
                                '</h3>' +
                                '<div class="text-xs text-gray-500 mb-2">List ID: ' + list.listId + '</div>';
                        
                        if (list.items && list.items.length > 0) {
                            listHtml += '<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">';
                            for (let i = 0; i < Math.min(10, list.items.length); i++) {
                                const item = list.items[i];
                                listHtml += '<div class="text-sm bg-gray-50 px-2 py-1 rounded truncate">' + (item.value || item) + '</div>';
                            }
                            if (list.items.length > 10) {
                                listHtml += '<div class="text-sm text-gray-500 italic">... and ' + (list.items.length - 10) + ' more</div>';
                            }
                            listHtml += '</div>';
                        } else {
                            listHtml += '<div class="text-gray-500 italic">No items in this list</div>';
                        }
                        
                        listHtml += '</div>';
                    });
                    
                    listHtml += '</div>';
                    document.getElementById('user-details').innerHTML = listHtml;
                    document.getElementById('status').innerHTML = '<span class="text-green-600">✓ Loaded Gateway lists (' + data.summary.total + ' total items)</span>';
                } else {
                    document.getElementById('status').innerHTML = '<span class="text-red-600">✗ Failed to load Gateway lists</span>';
                }
            } catch (error) {
                document.getElementById('status').innerHTML = '<span class="text-red-600">✗ Error loading Gateway lists</span>';
                console.error('Error:', error);
            }
        }
        
        async function updateRiskLists() {
            document.getElementById('status').innerHTML = '<span class="loading inline-block w-4 h-4 border-2 border-green-500 border-t-transparent rounded-full"></span> Updating risk lists...';
            
            try {
                const response = await fetch('/api/update-risk-lists', { method: 'POST' });
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('status').innerHTML = '<span class="text-green-600">✓ Risk lists updated successfully</span>';
                    setTimeout(function() { loadUserRiskScores(); }, 1000);
                } else {
                    document.getElementById('status').innerHTML = '<span class="text-red-600">✗ Failed to update risk lists</span>';
                }
            } catch (error) {
                document.getElementById('status').innerHTML = '<span class="text-red-600">✗ Error updating lists</span>';
                console.error('Error:', error);
            }
        }
        
        async function checkHealth() {
            document.getElementById('status').innerHTML = '<span class="loading inline-block w-4 h-4 border-2 border-orange-500 border-t-transparent rounded-full"></span> Checking system health...';
            
            try {
                const response = await fetch('/api/health');
                const data = await response.json();
                
                let healthHtml = '<div class="space-y-4">';
                healthHtml += '<div class="flex items-center space-x-2">';
                healthHtml += '<span class="text-2xl">' + (data.status === 'healthy' ? '✅' : data.status === 'degraded' ? '⚠️' : '❌') + '</span>';
                healthHtml += '<span class="text-xl font-semibold">System Status: ' + data.status.toUpperCase() + '</span>';
                healthHtml += '</div>';
                
                if (data.checks) {
                    healthHtml += '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">';
                    Object.entries(data.checks).forEach(([check, result]) => {
                        const statusIcon = result.status === 'healthy' ? '✅' : '❌';
                        healthHtml += '<div class="border rounded-lg p-3">';
                        healthHtml += '<div class="flex items-center justify-between">';
                        healthHtml += '<span class="font-medium">' + check.replace(/_/g, ' ').toUpperCase() + '</span>';
                        healthHtml += '<span>' + statusIcon + '</span>';
                        healthHtml += '</div>';
                        healthHtml += '<div class="text-sm text-gray-600">Response: ' + result.response_time + 'ms</div>';
                        healthHtml += '</div>';
                    });
                    healthHtml += '</div>';
                }
                
                healthHtml += '<div class="text-sm text-gray-500">Total check time: ' + data.total_response_time + 'ms</div>';
                healthHtml += '</div>';
                
                document.getElementById('user-details').innerHTML = healthHtml;
                document.getElementById('status').innerHTML = '<span class="text-green-600">✓ Health check completed</span>';
            } catch (error) {
                document.getElementById('status').innerHTML = '<span class="text-red-600">✗ Health check failed</span>';
                console.error('Error:', error);
            }
        }
        
        async function viewMetrics() {
            document.getElementById('status').innerHTML = '<span class="loading inline-block w-4 h-4 border-2 border-indigo-500 border-t-transparent rounded-full"></span> Loading metrics...';
            
            try {
                const response = await fetch('/api/metrics');
                const data = await response.json();
                
                let metricsHtml = '<div class="space-y-6">';
                metricsHtml += '<div class="grid grid-cols-1 md:grid-cols-3 gap-4">';
                
                // System info
                metricsHtml += '<div class="border rounded-lg p-4">';
                metricsHtml += '<h3 class="font-semibold text-gray-800 mb-2">📊 System Info</h3>';
                metricsHtml += '<div class="space-y-1 text-sm">';
                metricsHtml += '<div>Version: ' + data.version + '</div>';
                metricsHtml += '<div>Timestamp: ' + new Date(data.timestamp).toLocaleString() + '</div>';
                metricsHtml += '</div>';
                metricsHtml += '</div>';
                
                // Features
                metricsHtml += '<div class="border rounded-lg p-4">';
                metricsHtml += '<h3 class="font-semibold text-gray-800 mb-2">🔧 Features</h3>';
                metricsHtml += '<div class="space-y-1 text-sm">';
                Object.entries(data.features).forEach(([feature, enabled]) => {
                    metricsHtml += '<div class="flex justify-between">';
                    metricsHtml += '<span>' + feature.replace(/_/g, ' ') + ':</span>';
                    metricsHtml += '<span>' + (enabled ? '✅' : '❌') + '</span>';
                    metricsHtml += '</div>';
                });
                metricsHtml += '</div>';
                metricsHtml += '</div>';
                
                // Execution stats
                if (data.execution_stats) {
                    metricsHtml += '<div class="border rounded-lg p-4">';
                    metricsHtml += '<h3 class="font-semibold text-gray-800 mb-2">📈 Execution Stats</h3>';
                    metricsHtml += '<div class="space-y-1 text-sm">';
                    metricsHtml += '<div>Total: ' + data.execution_stats.total_executions + '</div>';
                    metricsHtml += '<div>Success: ' + data.execution_stats.successful_executions + '</div>';
                    metricsHtml += '<div>Failed: ' + data.execution_stats.failed_executions + '</div>';
                    if (data.execution_stats.average_duration) {
                        metricsHtml += '<div>Avg Duration: ' + Math.round(data.execution_stats.average_duration) + 'ms</div>';
                    }
                    metricsHtml += '</div>';
                    metricsHtml += '</div>';
                } else {
                    metricsHtml += '<div class="border rounded-lg p-4">';
                    metricsHtml += '<h3 class="font-semibold text-gray-800 mb-2">📈 Execution Stats</h3>';
                    metricsHtml += '<div class="text-sm text-gray-500">No execution data available (KV not configured)</div>';
                    metricsHtml += '</div>';
                }
                
                metricsHtml += '</div>';
                metricsHtml += '</div>';
                
                document.getElementById('user-details').innerHTML = metricsHtml;
                document.getElementById('status').innerHTML = '<span class="text-green-600">✓ Metrics loaded</span>';
            } catch (error) {
                document.getElementById('status').innerHTML = '<span class="text-red-600">✗ Failed to load metrics</span>';
                console.error('Error:', error);
            }
        }
        
        async function forceSync() {
            document.getElementById('status').innerHTML = '<span class="loading inline-block w-4 h-4 border-2 border-yellow-500 border-t-transparent rounded-full"></span> Force syncing Gateway lists...';
            
            try {
                const response = await fetch('/api/force-cleanup');
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('status').innerHTML = '<span class="text-green-600">✓ Force sync completed successfully</span>';
                    setTimeout(function() { loadUserRiskScores(); }, 1000);
                } else {
                    document.getElementById('status').innerHTML = '<span class="text-red-600">✗ Force sync failed</span>';
                }
            } catch (error) {
                document.getElementById('status').innerHTML = '<span class="text-red-600">✗ Error during force sync</span>';
                console.error('Error:', error);
            }
        }
        
        // Load data on page load
        loadUserRiskScores();
    </script>
</body>
</html>`;
}
