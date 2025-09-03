/**
 * Main application script for Vulnerability Trace Viewer
 */
document.addEventListener('DOMContentLoaded', async () => {
    // Make sure the window object has all expected components
    console.log('Checking dependencies:');
    if (!window.d3) {
        console.error('D3 not loaded! Application will not function correctly.');
    } else {
        console.log('✓ D3 is loaded, version:', d3.version);
    }
    
    if (!window.GraphRenderer) {
        console.error('GraphRenderer not loaded! Application will not function correctly.');
    } else {
        console.log('✓ GraphRenderer is loaded');
    }
    
    if (!window.TraceParser) {
        console.error('TraceParser not loaded! Application will not function correctly.');
    } else {
        console.log('✓ TraceParser is loaded');
    }
    
    // Load D3 Sankey early, before we need it
    console.log('Pre-loading D3 Sankey module...');
    try {
        await window.loadD3Sankey();
        if (typeof d3.sankey === 'function') {
            console.log('✓ D3 Sankey loaded successfully');
        } else {
            console.warn('⚠️ D3 Sankey module loaded but sankey function is not available');
        }
    } catch (error) {
        console.error('Failed to pre-load D3 Sankey:', error);
        console.log('Will try to load it when needed');
    }
    
    // Initialize components
    try {
        console.log('Initializing application components...');
        // Initialize the TraceParser
        const traceParser = new window.TraceParser();
        
        // Check if GraphRenderer is available
        if (typeof window.GraphRenderer !== 'function') {
            console.error('GraphRenderer is not available!', typeof window.GraphRenderer);
            throw new Error('GraphRenderer constructor is not available. Check script loading order.');  
        }
        
        const graphRenderer = new window.GraphRenderer('trace-graph');
        console.log('GraphRenderer initialized successfully');
        
        // Track layout mode
        let usingSankeyLayout = false;
        
        // Setup file input handler
        const fileInput = document.getElementById('file-input');
        fileInput.addEventListener('change', handleFileSelection);
        
        // Setup trace file load button
        const loadTraceButton = document.getElementById('load-trace-file');
        
        if (loadTraceButton) {
            console.log("Found load trace file button, adding click event listener");
            
            // Add click event listener to trigger file dialog
            loadTraceButton.addEventListener('click', function() {
                fileInput.click();
            });
        } else {
            console.error("Could not find load-trace-file button!");
        }
        
        // Setup layout toggle button
        const toggleLayoutButton = document.getElementById('toggle-layout');
        
        if (toggleLayoutButton) {
            console.log("Found toggle layout button, adding click event listener");
            
            // Add click event listener to toggle layout
            toggleLayoutButton.addEventListener('click', async function() {
                // Check if D3 Sankey is available, try to load it if not
                if (typeof d3.sankey !== 'function') {
                    console.log('D3 Sankey not available, attempting to load it...');
                    try {
                        await window.loadD3Sankey();
                        console.log('D3 Sankey loaded successfully:', typeof d3.sankey === 'function');
                    } catch (error) {
                        console.error('Failed to load D3 Sankey:', error);
                        alert('Unable to load the Sankey layout module. The layout will not change.');
                        return;
                    }
                }
                
                // Continue with the layout toggle now that Sankey is available
                
                // Toggle layout mode
                usingSankeyLayout = !usingSankeyLayout;
                console.log(`Toggle Sankey layout: ${usingSankeyLayout ? 'ENABLED' : 'DISABLED'}`);
                
                // Update button appearance
                if (usingSankeyLayout) {
                    toggleLayoutButton.classList.add('active');
                    toggleLayoutButton.textContent = 'Show Standard View';
                } else {
                    toggleLayoutButton.classList.remove('active');
                    toggleLayoutButton.textContent = 'Show Sankey View';
                }
                
                // Re-render with current data if available
                if (graphRenderer.data) {
                    console.log('Setting useSankeyLayout property on graphRenderer');
                    graphRenderer.useSankeyLayout = usingSankeyLayout;
                    graphRenderer.forceRerender = true;
                    console.log(`GraphRenderer.useSankeyLayout is now: ${graphRenderer.useSankeyLayout}`);
                    graphRenderer.updateSize();
                } else {
                    console.warn('No data available in graphRenderer, toggle will take effect when data is loaded');
                }
            });
        } else {
            console.error("Could not find toggle-layout button!");
        }
        
        // Setup sidebar resizing and toggling
        setupSidebar();
    
        /**
         * Handle file selection from file input
         * @param {Event} event - File input change event
         */
        async function handleFileSelection(event) {
            const file = event.target.files[0];
            if (!file) return;
            
            try {
                let xmlContent;
                
                // Check if it's a zip file
                if (file.name.toLowerCase().endsWith('.zip')) {
                    xmlContent = await extractXmlFromZip(file);
                } else {
                    xmlContent = await file.text();
                }
                
                processXmlContent(xmlContent);
            } catch (error) {
                showError(`Error processing file: ${error.message}`);
            }
        }
    
        /**
         * Extract XML content from a ZIP file
         * @param {File} zipFile - ZIP file object
         * @returns {Promise<string>} XML content
         */
        async function extractXmlFromZip(zipFile) {
            // Load the ZIP file
            const zipContent = await JSZip.loadAsync(zipFile);
            
            // Find XML files in the ZIP
            let xmlFiles = Object.keys(zipContent.files).filter(filename => 
                filename.toLowerCase().endsWith('.xml')
            );
            
            if (xmlFiles.length === 0) {
                throw new Error('No XML files found in the ZIP archive');
            }
            
            // Use the first XML file found
            return await zipContent.files[xmlFiles[0]].async('text');
        }
    
        /**
         * Load fallback sample data when actual data can't be loaded
         */
        function loadFallbackData() {
            console.log("Loading fallback sample data");
            
            // Create minimal sample data that will render without errors
            const sampleData = {
                vulnerabilityInfo: {
                    uuid: 'sample-12345',
                    ruleId: 'sql-injection',
                    applicationName: 'Sample Application',
                    applicationId: 'app-123',
                    title: 'Sample SQL Injection Vulnerability',
                    link: '#'
                },
                requestInfo: {
                    method: 'GET',
                    protocol: 'http',
                    version: '1.1',
                    port: '8080',
                    uri: '/search',
                    queryString: 'q=user\'+OR+1=1--',
                    headers: [
                        { name: 'Host', value: 'example.com' },
                        { name: 'User-Agent', value: 'Mozilla/5.0' }
                    ],
                    parameters: [
                        { name: 'q', value: "user' OR 1=1--" }
                    ]
                },
                events: [
                    {
                        objectId: 'event-1',
                        type: 'Creation',
                        isSourceEvent: true,
                        signature: 'web.SearchController.search(String)',
                        methodSignature: 'SearchController.search("user\' OR 1=1--")',
                        label: 'Parameter input',
                        taintedData: "user' OR 1=1--"
                    },
                    {
                        objectId: 'event-2',
                        type: 'P2O',
                        isPropagationEvent: true,
                        signature: 'java.lang.StringBuilder.append(String)',
                        methodSignature: 'StringBuilder.append("user\' OR 1=1--")',
                        label: 'SQL Construction',
                        taintedData: "SELECT * FROM users WHERE name=\'user\' OR 1=1--'"
                    },
                    {
                        objectId: 'event-3',
                        type: 'Trigger',
                        isTriggerEvent: true,
                        signature: 'java.sql.Statement.executeQuery(String)',
                        methodSignature: 'Statement.executeQuery("SELECT * FROM users WHERE name=\'user\' OR 1=1--\'")',
                        label: 'Vulnerable Database Query',
                        taintedData: "SELECT * FROM users WHERE name=\'user\' OR 1=1--'"
                    }
                ],
                nodes: [
                    {
                        id: 'request',
                        type: 'http-request',
                        label: 'HTTP Request with untrusted \'q\' parameter',
                        methodSignature: 'GET /search?q=user\'+OR+1=1--',
                        taintedData: "user' OR 1=1--",
                        details: { 
                            parameters: [{ name: 'q', value: "user' OR 1=1--" }],
                            method: 'GET',
                            uri: '/search',
                            queryString: 'q=user\'+OR+1=1--'
                        }
                    },
                    {
                        id: 'event-1',
                        type: 'trace-event',
                        label: 'Source: Extract \'q\' from request',
                        methodSignature: 'SearchController.search("user\' OR 1=1--")',
                        taintedData: "user' OR 1=1--",
                        details: { 
                            signature: 'web.SearchController.search(String)',
                            type: 'Creation'
                        }
                    },
                    {
                        id: 'event-2',
                        type: 'trace-event',
                        label: 'Propagation: Build SQL query with untrusted data',
                        methodSignature: 'StringBuilder.append("user\' OR 1=1--")',
                        taintedData: "SELECT * FROM users WHERE name='user' OR 1=1--'",
                        details: { 
                            signature: 'java.lang.StringBuilder.append(String)',
                            type: 'P2O'
                        }
                    },
                    {
                        id: 'event-3',
                        type: 'trace-event',
                        label: 'Rule Violated: SQL Injection',
                        methodSignature: 'Statement.executeQuery("SELECT * FROM users WHERE name=\'user\' OR 1=1--\'")',
                        taintedData: "SELECT * FROM users WHERE name='user' OR 1=1--'",
                        details: { 
                            signature: 'java.sql.Statement.executeQuery(String)',
                            type: 'Trigger'
                        }
                    }
                ],
                edges: [
                    { source: 'request', target: 'event-1' },
                    { source: 'event-1', target: 'event-2' },
                    { source: 'event-2', target: 'event-3' }
                ]
            };
            
            // Process the sample data as if it came from XML
            processXmlContent(JSON.stringify(sampleData));
        }
        
        /**
         * Load sample data from the extracted file
         */
        async function loadSampleData() {
            try {
                console.log("Loading sample data...");
                
                // No loading message
                
                // Fetch the sample XML file with explicit path and no caching
                const fetchUrl = 'extracted/vulnerabilities2025-08-17.xml';
                console.log("Fetching from URL:", fetchUrl);
                
                const response = await fetch(fetchUrl, {
                    method: 'GET',
                    cache: 'no-store',
                    headers: {
                        'Cache-Control': 'no-cache'
                    }
                });
                
                if (!response.ok) {
                    throw new Error(`Failed to fetch sample data: ${response.status} ${response.statusText}`);
                }
                
                console.log("Sample data fetched successfully");
                
                // Get the response text
                const xmlContent = await response.text();
                console.log("XML content length:", xmlContent.length);
                console.log("XML content snippet:", xmlContent.substring(0, 100) + "...");
                
                // Process the XML content
                if (xmlContent.length > 0) {
                    processXmlContent(xmlContent);
                } else {
                    throw new Error("Empty XML content received");
                }
            } catch (error) {
                console.error("Error loading sample data:", error);
                console.log("Using fallback sample data instead");
                
                // No loading message
                
                // Use fallback data instead
                setTimeout(() => {
                    loadFallbackData();
                }, 1000); // Give user a moment to see the message
            }
        }
    
        /**
         * Process XML content and visualize the trace
         * @param {string} xmlContent - XML content as string
         */
        function processXmlContent(xmlContent) {
            try {
                console.log("Processing XML content...");
                
                // Parse the XML content
                const traceData = traceParser.parseXmlContent(xmlContent);
                console.log("XML parsed successfully:");
                console.log("Events count:", traceData.events.length);
                console.log("Nodes count:", traceData.nodes.length);
                console.log("Edges count:", traceData.edges.length);
                
                // Display vulnerability info
                console.log("Displaying vulnerability info...");
                displayVulnerabilityInfo(traceData.vulnerabilityInfo);
                
                // Update vulnerability banner
                console.log("Updating vulnerability banner...");
                updateVulnerabilityBanner(traceData.vulnerabilityInfo);
                
                // Set up node click handler
                console.log("Setting up node click handler...");
                graphRenderer.setNodeClickHandler(node => {
                    displayNodeDetails(node);
                });
                
                // Render the graph with a longer delay to ensure DOM is ready
                console.log("Setting up graph rendering with delay...");
                setTimeout(() => {
                    console.log("Now rendering graph with nodes:", traceData.nodes.length);
                    // Debug log of all nodes that will be sent to rendering
                    console.log("Node details before rendering:");
                    traceData.nodes.forEach((node, i) => {
                        console.log(`Node ${i}: id=${node.id}, type=${node.type}`);
                    });
                    graphRenderer.render({
                        nodes: traceData.nodes,
                        edges: traceData.edges
                    });
                }, 500);
                
                // Display HTTP request details initially
                console.log("Setting up initial node details display...");
                const requestNode = traceData.nodes.find(node => node.type === 'http-request');
                if (requestNode) {
                    console.log("Found HTTP request node, displaying details");
                    displayNodeDetails(requestNode);
                } else {
                    console.log("No HTTP request node found");
                }
            } catch (error) {
                console.error("Error in processXmlContent:", error);
                showError(`Error visualizing trace: ${error.message}`);
            }
        }
    
        /**
         * Update the vulnerability details panel
         * @param {Object} vulnInfo - Vulnerability information object
         */
        function updateVulnerabilityBanner(vulnInfo) {
            // Update all vulnerability detail elements
            document.getElementById('vuln-name').textContent = vulnInfo.title || 'Unknown Vulnerability';
            document.getElementById('vuln-rule-id').textContent = vulnInfo.ruleId || 'N/A';
            document.getElementById('vuln-app').textContent = vulnInfo.applicationName || 'N/A';
            document.getElementById('vuln-uuid').textContent = vulnInfo.uuid || 'N/A';
            
            const vulnLink = document.getElementById('vuln-link');
            if (vulnInfo.link) {
                vulnLink.href = vulnInfo.link;
                vulnLink.style.display = '';
            } else {
                vulnLink.style.display = 'none';
            }
            
            // Show the vulnerability details panel in collapsed state
            const vulnDetailsPanel = document.getElementById('vulnerability-details');
            vulnDetailsPanel.style.display = 'block';
            vulnDetailsPanel.classList.add('collapsed'); // Start in collapsed state
            
            // Add click handler for collapsing/expanding
            if (!vulnDetailsPanel.hasClickHandler) {
                vulnDetailsPanel.addEventListener('click', function(event) {
                    // Toggle collapsed class
                    this.classList.toggle('collapsed');
                    
                    // Prevent event propagation to graph container
                    event.stopPropagation();
                    
                    // Add animation class to enhance the transition
                    this.classList.add('transitioning');
                    setTimeout(() => {
                        this.classList.remove('transitioning');
                    }, 300);
                });
                vulnDetailsPanel.hasClickHandler = true;
            }
        }
        
        /**
         * Display vulnerability information (now only updates the banner)
         * @param {Object} vulnInfo - Vulnerability information object
         */
        function displayVulnerabilityInfo(vulnInfo) {
            // This function now only updates the banner via updateVulnerabilityBanner
            // Sidebar vulnerability details section has been removed
        }
    
        /**
         * Display node details in the sidebar
         * @param {Object} node - Node object
         */
        function displayNodeDetails(node) {
            console.log("Displaying node details:", node);
            const nodeInfoContainer = document.getElementById('node-info');
            
            if (!nodeInfoContainer) {
                console.error("node-info container not found!");
                return;
            }
            
            // Set padding and minimum height but no border
            nodeInfoContainer.style.padding = "10px";
            nodeInfoContainer.style.minHeight = "200px";
            
            // Check if this is a collapsed group node
            if (node.isCollapsedGroup && node.originalNodes) {
                console.log("Displaying collapsed group details");
                displayCollapsedGroupDetails(node, nodeInfoContainer);
            } else if (node.type === 'http-request') {
                console.log("Displaying HTTP request details");
                displayHttpRequestDetails(node.details, nodeInfoContainer);
            } else if (node.type === 'trace-event') {
                console.log("Displaying event details");
                displayEventDetails(node.details, nodeInfoContainer);
            } else if (node.type === 'route') {
                console.log("Displaying route details");
                displayRouteDetails(node, nodeInfoContainer);
            } else {
                console.log("Node type unknown, showing default message");
                nodeInfoContainer.innerHTML = '<p>Select a node to view details</p>';
            }
        }
    
        /**
         * Display HTTP request details
         * @param {Object} request - Request information
         * @param {HTMLElement} container - Container element
         */
        function displayHttpRequestDetails(request, container) {
            // Format the HTTP request as a raw HTTP request
            const method = request.method || 'GET';
            const uri = request.uri || '/';
            const queryString = request.queryString ? `?${request.queryString}` : '';
            const protocol = `${request.protocol || 'http'}/${request.version || '1.1'}`;
            
            // Build the request line and headers
            let rawRequest = `${method} ${uri}${queryString} ${protocol.toUpperCase()}\n`;
            
            // Add headers
            if (request.headers && request.headers.length > 0) {
                request.headers.forEach(header => {
                    rawRequest += `${header.name}: ${header.value}\n`;
                });
            }
            
            // Add empty line before body
            rawRequest += '\n';
            
            // Add body if present
            if (request.body && request.body.trim()) {
                rawRequest += request.body;
            }
            
            // Check if we have parameters to highlight
            const trackedParams = request.parameters || [];
            let trackedParamsHtml = '';
            
            if (trackedParams.length > 0) {
                trackedParamsHtml = `
                    <div class="tracked-params-section">
                        <h4>Tracked Parameters</h4>
                        <ul class="params-list">
                            ${trackedParams.map(param => `
                                <li>
                                    <strong>${escapeHtml(param.name)}:</strong> 
                                    <span class="tracked-parameter">${escapeHtml(param.value)}</span>
                                </li>
                            `).join('')}
                        </ul>
                    </div>
                `;
            }
            
            // Highlight any tracked parameters in the raw request
            let highlightedRequest = rawRequest;
            trackedParams.forEach(param => {
                // Replace all instances of the parameter value with a highlighted version
                const regex = new RegExp(`${escapeHtml(param.value)}`, 'g');
                highlightedRequest = highlightedRequest.replace(
                    regex, 
                    `<span class="tracked-parameter">${escapeHtml(param.value)}</span>`
                );
                
                // Also highlight the parameter name in the query string
                const paramNameRegex = new RegExp(`${param.name}=`, 'g');
                highlightedRequest = highlightedRequest.replace(
                    paramNameRegex, 
                    `<span class="tracked-parameter-name">${param.name}</span>=`
                );
            });
            
            // Build the full HTML
            container.innerHTML = `
                <div class="info-section">
                    <h3>Event: HTTP Request</h3>
                    <div class="raw-http-request">
                        <pre class="http-request-content" style="white-space: pre-wrap; word-break: break-all;">${highlightedRequest}</pre>
                    </div>
                    ${trackedParamsHtml}
                </div>
            `;
        }
    
        /**
         * Apply taint ranges to content with color highlighting
         * @param {string} content - Content to highlight
         * @param {Array} taintRanges - Array of taint range objects
         * @param {boolean} truncate - Whether to truncate long content (default: false) - DISABLED, now always shows full content
         * @param {boolean} skipEscaping - Whether to skip HTML escaping for content that may already be escaped (default: true)
         * @returns {string} HTML with highlighted content
         */
        function applyTaintRanges(content, taintRanges, truncate = false, skipEscaping = false) {
            // Force truncate to be false - we want to show all content in the panel
            truncate = false;
            // Check if content might already have HTML entities
            const mayHaveEntities = content && (content.includes('&lt;') || content.includes('&gt;') || 
                                               content.includes('&amp;') || content.includes('&quot;') || 
                                               content.includes('&#'));
            
            // Determine if we should skip escaping based on the parameter or content analysis
            const shouldSkipEscaping = skipEscaping || mayHaveEntities;
            
            // Simply return content with proper escaping if there are no taint ranges
            if (!content || !taintRanges || taintRanges.length === 0) {
                return shouldSkipEscaping ? content : escapeHtml(content);
            }
            
            // Convert the content to a character array for easier manipulation
            // but don't HTML escape here - we'll handle it character by character
            const contentChars = [...content];
            
            // Create a map of positions to tag names for highlighting
            const highlightMap = {};
            
            // Track taint range boundaries for smart truncation
            let minTaintStart = content.length;
            let maxTaintEnd = 0;
            
            // Process each taint range
            taintRanges.forEach(range => {
                if (!range.range) return;
                
                // Check if the range contains multiple comma-separated ranges
                if (range.range.includes(',')) {
                    // Handle comma-separated ranges (e.g., "120:127,112:119,104:111")
                    const rangeList = range.range.split(',');
                    
                    // Process each range in the list
                    rangeList.forEach(singleRange => {
                        // Parse the range format (e.g., "0:7")
                        // In Java substring style, start is inclusive, end is exclusive
                        const [start, end] = singleRange.split(':').map(num => parseInt(num, 10));
                        
                        if (isNaN(start) || isNaN(end) || start < 0 || end > contentChars.length) {
                            return; // Invalid range
                        }
                        
                        // Update min/max positions for truncation later
                        minTaintStart = Math.min(minTaintStart, start);
                        maxTaintEnd = Math.max(maxTaintEnd, end);
                        
                        // Mark start and end positions (inclusive start, exclusive end)
                        for (let i = start; i < end; i++) {
                            highlightMap[i] = range.tag || 'tainted';
                        }
                    });
                } else {
                    // Handle single range format (e.g., "0:7" or "90:97")
                    // In Java substring style, start is inclusive, end is exclusive
                    const [start, end] = range.range.split(':').map(num => parseInt(num, 10));
                    
                    if (isNaN(start) || isNaN(end) || start < 0 || end > contentChars.length) {
                        return; // Invalid range
                    }
                    
                    // Update min/max positions for truncation later
                    minTaintStart = Math.min(minTaintStart, start);
                    maxTaintEnd = Math.max(maxTaintEnd, end);
                    
                    // Mark start and end positions (inclusive start, exclusive end)
                    for (let i = start; i < end; i++) {
                        highlightMap[i] = range.tag || 'tainted';
                    }
                }
            });
            
            // We're showing all content without truncation
            const startIdx = 0;
            const endIdx = contentChars.length;
            const truncationPrefix = '';
            const truncationSuffix = '';
            
            // Apply highlights by inserting span tags
            let result = truncationPrefix;
            let currentTag = null;
            let inHighlight = false;
            
            for (let i = startIdx; i < endIdx; i++) {
                const tag = highlightMap[i];
                const char = contentChars[i];
                
                // If we're entering a new highlight or changing highlight type
                if (tag && (!inHighlight || tag !== currentTag)) {
                    // Close previous highlight if needed
                    if (inHighlight) {
                        result += '</span>';
                    }
                    
                    // Start new highlight
                    result += `<span class="taint-highlight taint-${tag}">`;
                    inHighlight = true;
                    currentTag = tag;
                }
                // If we're exiting a highlight
                else if (!tag && inHighlight) {
                    result += '</span>';
                    inHighlight = false;
                    currentTag = null;
                }
                
                // Add the character with appropriate HTML escaping if needed
                // If we're skipping escaping (for pre-escaped content), output characters as-is
                if (shouldSkipEscaping) {
                    result += char;
                } else {
                    // Otherwise, do normal HTML escaping
                    switch (char) {
                        case '<':
                            result += '&lt;';
                            break;
                        case '>':
                            result += '&gt;';
                            break;
                        case '&':
                            result += '&amp;';
                            break;
                        case '"':
                            result += '&quot;';
                            break;
                        case "'":
                            result += "&#039;";
                            break;
                        default:
                            result += char;
                    }
                }
            }
            
            // Close any open highlight at the end
            if (inHighlight) {
                result += '</span>';
            }
            
            result += truncationSuffix;
            
            return result;
        }
    
        /**
         * Display event details
         * @param {Object} event - Event information
         * @param {HTMLElement} container - Container element
         */
        function displayEventDetails(event, container) {
            const isDataFlow = event.type === 'P2O' || event.type === 'O2P' || event.type === 'P2P' || 
                               event.type === 'O2R' || event.type === 'P2R' || event.type === 'Propagator';
                               
            const isViolation = event.type === 'Trigger' || event.isTriggerEvent;
            
            // Process object data with taint ranges
            let objectDataHtml = '';
            if (event.objectData && event.objectData.decoded) {
                // Decode any HTML entities in the object data
                const decodedContent = decodeHtml(event.objectData.decoded);
                
                // For data flow events, show as Source or Target
                let label = 'Object:';
                if (isDataFlow) {
                    // Determine if this is source or target based on type
                    if (event.type === 'P2O' || event.type === 'O2P') {
                        label = 'Source (Object):';
                    } else {
                        label = 'Target (Object):';
                    }
                }
                
                // Only apply taint highlighting for non-Source events
                // But always apply highlighting for Violation events
                let displayContent;
                if ((event.isSourceEvent || event.type === 'Creation' || event.type === 'Source') && !isViolation) {
                    // Source events don't have tainted data in the source fields - don't highlight
                    // Never truncate or ellipse Source event data - show the full content
                    displayContent = decodedContent;
                        
                    objectDataHtml = `
                        <div class="info-item">
                            <strong>${label}</strong> 
                            <pre class="decoded-content">${displayContent}</pre>
                        </div>
                    `;
                } else {
                    // For Data Flow or Violation events, apply highlighting
                    // Use skipEscaping=true to prevent double encoding
                    const highlightedContent = applyTaintRanges(decodedContent, event.taintRanges, false, true);
                    
                    objectDataHtml = `
                        <div class="info-item">
                            <strong>${label}</strong> 
                            <pre class="decoded-content with-taint-highlights">${highlightedContent}</pre>
                        </div>
                    `;
                }
            }
            
            // Process parameter data if available
            let paramDataHtml = '';
            if (event.args && event.args.length > 0) {
                // Just use the parameter values directly without prefixes
                const argsContent = event.args.map((arg, index) => {
                    // Handle null or undefined
                    if (arg.decodedValue === undefined || arg.decodedValue === null) {
                        return `null`;
                    }
                    
                    // Use the parameter value directly, but decode any HTML entities
                    return `${decodeHtml(arg.decodedValue)}`;
                }).join('\n');
                
                // For data flow events, show as Source or Target
                let label = 'Parameters:';
                if (isDataFlow) {
                    // Determine if this is source or target
                    if (event.type === 'P2O' || event.type === 'P2P') {
                        label = 'Source (Parameter):';
                    } else {
                        label = 'Target (Parameter):';
                    }
                }
                
                // Only apply taint highlighting for non-Source events
                // But always apply highlighting for Violation events
                let displayContent;
                if ((event.isSourceEvent || event.type === 'Creation' || event.type === 'Source') && !isViolation) {
                    // Source events don't have tainted data in the source fields - don't highlight
                    // Never truncate or ellipse Source event data - show the full content
                    displayContent = argsContent;
                    
                    paramDataHtml = `
                        <div class="info-item">
                            <strong>${label}</strong> 
                            <pre class="decoded-content">${displayContent}</pre>
                        </div>
                    `;
                } else {
                    // For Data Flow or Violation events, apply highlighting
                    // Set skipEscaping to true for parameter data to avoid double-encoding
                    const highlightedContent = applyTaintRanges(argsContent, event.taintRanges, false, true);
                    
                    paramDataHtml = `
                        <div class="info-item">
                            <strong>${label}</strong> 
                            <pre class="decoded-content with-taint-highlights">${highlightedContent}</pre>
                        </div>
                    `;
                }
            }
            
            // Process return data with taint ranges
            let returnDataHtml = '';
            if (event.returnData && event.returnData.decoded) {
                // Decode any HTML entities in the return data
                const decodedContent = decodeHtml(event.returnData.decoded);
                // Use skipEscaping=true to prevent double encoding
                // For violation events, use parameter-specific taint ranges if available
                const taintRangesToUse = (isViolation && event.parameterTaintRanges) ? event.parameterTaintRanges : event.taintRanges;
                const highlightedContent = applyTaintRanges(decodedContent, taintRangesToUse, false, true);
                
                // For data flow events, consistently show as Source or Target
                let label = 'Return:';
                if (isDataFlow) {
                    // For all data flow events that include return data, it's the target
                    label = 'Target:';
                    if (event.type === 'O2R' || event.type === 'P2R') {
                        label = 'Target (Return):';
                    }
                } else if (isViolation) {
                    // For violation events, explicitly show it's the parameter
                    label = 'Parameter:';
                }
                
                returnDataHtml = `
                    <div class="info-item">
                        <strong>${label}</strong> 
                        <pre class="decoded-content with-taint-highlights">${highlightedContent}</pre>
                    </div>
                `;
            }
            
            // Fallback to legacy decoded object if no specific data is available
            let decodedContent = '';
            if (!objectDataHtml && !paramDataHtml && !returnDataHtml && event.decodedObject) {
                // Decode any HTML entities in the decoded object
                const decodedContent = decodeHtml(event.decodedObject);
                // Use skipEscaping=true to prevent double encoding
                const highlightedContent = applyTaintRanges(decodedContent, event.taintRanges, false, true);
                decodedContent = `
                    <div class="info-item">
                        <strong>Decoded Content:</strong> 
                        <pre class="decoded-content with-taint-highlights">${highlightedContent}</pre>
                    </div>
                `;
            }
            
            // Show taint ranges summary as Tags
            let taintRangesHtml = '';
            if (event.taintRanges && event.taintRanges.length > 0) {
                taintRangesHtml = `
                    <div class="info-item">
                        <strong>Tags:</strong>
                        <ul class="taint-ranges-list">
                            ${event.taintRanges.map(range => `
                                <li>
                                    <span class="taint-tag taint-${range.tag || 'default'}">${escapeHtml(range.tag || '')}</span>: 
                                    <span class="taint-range">${escapeHtml(range.range || '')}</span>
                                </li>
                            `).join('')}
                        </ul>
                    </div>
                `;
            }
            
            // Format the stack trace if present
            let stackTraceHtml = '';
            if (event.stack && event.stack.length > 0) {
                stackTraceHtml = `
                    <div class="info-item stack-trace">
                        <strong>Stack Trace:</strong>
                        <div class="stack-trace-container">
                            <pre class="stack-trace-content">${event.stack.map(escapeHtml).join('\n')}</pre>
                        </div>
                    </div>
                `;
            }
            
            // Add XML display with decoded content
            let xmlHtml = '';
            if (event.originalXml) {
                // Parse the XML to extract and decode Base64 content
                const parser = new DOMParser();
                const xmlDoc = parser.parseFromString(event.originalXml, "text/xml");
                
                // Make a copy of the original XML for display
                let decodedXml = event.originalXml;
                
                try {
                    // Try to find and decode object tag content
                    const objectEl = xmlDoc.querySelector("object");
                    if (objectEl && objectEl.textContent) {
                        try {
                            const decoded = atob(objectEl.textContent);
                            decodedXml = decodedXml.replace(objectEl.textContent, `[DECODED: ${decoded}]`);
                        } catch(e) {
                            // Not Base64, leave as-is
                        }
                    }
                    
                    // Try to find and decode return tag content
                    const returnEl = xmlDoc.querySelector("return");
                    if (returnEl && returnEl.textContent) {
                        try {
                            const decoded = atob(returnEl.textContent);
                            decodedXml = decodedXml.replace(returnEl.textContent, `[DECODED: ${decoded}]`);
                        } catch(e) {
                            // Not Base64, leave as-is
                        }
                    }
                    
                    // Try to find and decode arg tag content
                    const argEls = xmlDoc.querySelectorAll("arg");
                    if (argEls) {
                        argEls.forEach(argEl => {
                            if (argEl.textContent) {
                                try {
                                    const decoded = atob(argEl.textContent);
                                    decodedXml = decodedXml.replace(argEl.textContent, `[DECODED: ${decoded}]`);
                                } catch(e) {
                                    // Not Base64, leave as-is
                                }
                            }
                        });
                    }
                } catch(e) {
                    console.error("Error decoding XML content:", e);
                }
                
                xmlHtml = `
                    <div class="info-item">
                        <strong>Original XML (decoded):</strong>
                        <div class="xml-container">
                            <pre class="xml-content">${escapeHtml(decodedXml)}</pre>
                        </div>
                    </div>
                `;
            }
            
            // Build the full HTML with wrapping applied to all content
            container.innerHTML = `
                <div class="info-section">
                    <h3>Event: ${getDisplayType(event.type)}</h3>
                    <div class="info-item">
                        <strong>Signature:</strong> <pre class="signature" style="white-space: pre-wrap; word-break: break-all;">${escapeHtml(event.signature || '')}</pre>
                    </div>
                    
                    ${objectDataHtml.replace(/class="decoded-content/g, 'class="decoded-content" style="white-space: pre-wrap; word-break: break-all;"')}
                    ${paramDataHtml.replace(/class="decoded-content/g, 'class="decoded-content" style="white-space: pre-wrap; word-break: break-all;"')}
                    ${returnDataHtml.replace(/class="decoded-content/g, 'class="decoded-content" style="white-space: pre-wrap; word-break: break-all;"')}
                    ${decodedContent.replace(/class="decoded-content/g, 'class="decoded-content" style="white-space: pre-wrap; word-break: break-all;"')}
                    
                    ${taintRangesHtml}
                    ${stackTraceHtml}
                    ${event.sources && event.sources.length > 0 ? `
                    <div class="info-item">
                        <strong>Sources:</strong>
                        <ul class="sources-list">
                            ${event.sources.map(source => `
                                <li>
                                    <strong>${escapeHtml(source.type || '')}:</strong> 
                                    <span class="tracked-parameter">${escapeHtml(source.name || '')}</span>
                                </li>
                            `).join('')}
                        </ul>
                    </div>
                    ` : ''}
                    ${xmlHtml}
                </div>
            `;
        }
    
        /**
         * Display an error message to the user
         * @param {string} message - Error message
         */
        function showError(message) {
            console.error(message);
            alert(message);
        }
    
        /**
         * Display route details in the sidebar
         * @param {Object} node - Route node object
         * @param {HTMLElement} container - Container element
         */
        /**
         * Display details for a collapsed group node
         * @param {Object} node - Collapsed group node
         * @param {HTMLElement} container - Container element
         */
        function displayCollapsedGroupDetails(node, container) {
            // Extract information about the group
            const groupId = node.id;
            const groupSize = node.details.groupSize;
            const groupNodes = node.originalNodes;
            
            // Create HTML for group overview
            let html = `
                <div class="info-section">
                    <h3>Collapsed Group: ${escapeHtml(groupId)}</h3>
                    <div class="info-item">
                        <strong>Events in this group:</strong> ${groupSize}
                    </div>
                    <div class="info-item">
                        <strong>Event Type:</strong> 
                        <pre class="decoded-content" style="white-space: pre-wrap; word-break: break-all;">${escapeHtml(groupNodes[0].type === 'trace-event' ? getDisplayType(groupNodes[0].label) : groupNodes[0].type)}</pre>
                    </div>
            `;
            
            // Add signature from first node
            if (groupNodes[0].methodSignature) {
                html += `
                    <div class="info-item">
                        <strong>First Event Signature:</strong> 
                        <pre class="decoded-content" style="white-space: pre-wrap; word-break: break-all;">${escapeHtml(groupNodes[0].methodSignature)}</pre>
                    </div>
                `;
            }
            
            // Add list of all collapsed node IDs
            html += `
                <div class="info-item">
                    <strong>Individual Event IDs:</strong>
                    <ul class="group-nodes-list">
                        ${groupNodes.map(groupNode => `
                            <li>${escapeHtml(groupNode.id)}</li>
                        `).join('')}
                    </ul>
                </div>
            `;
            
            // Add a separator
            html += `<hr style="margin: 20px 0; border-top: 1px solid var(--border-color);">`;
            
            // Add details of the first event in the group
            html += `
                <div class="info-item">
                    <h4>Details of first event in group:</h4>
                </div>
            `;
            
            // Render the container with our overview
            container.innerHTML = html;
            
            // Create a sub-container for the first event details
            const detailsSubContainer = document.createElement('div');
            container.appendChild(detailsSubContainer);
            
            // Display details of the first event
            if (groupNodes[0].type === 'trace-event') {
                displayEventDetails(groupNodes[0].details, detailsSubContainer);
            } else {
                // Fallback if not a trace event
                detailsSubContainer.innerHTML = '<p>No detailed information available for this event type.</p>';
            }
        }

        function displayRouteDetails(node, container) {
            // Extract route information from the node details
            const route = node.details && node.details.route ? node.details.route : '/unknown';
            const method = node.details && node.details.method ? node.details.method : 'GET';
            
            // Build HTML for route details
            container.innerHTML = `
                <div class="info-section">
                    <h3>Event: Route</h3>
                    <div class="info-item">
                        <strong>Controller Information:</strong> 
                        <pre class="decoded-content" style="white-space: pre-wrap; word-break: break-all;">${escapeHtml(node.methodSignature || `Controller handling ${route}`)}</pre>
                    </div>
                    <div class="info-item">
                        <strong>HTTP Method:</strong> 
                        <pre class="decoded-content" style="white-space: pre-wrap; word-break: break-all;">${escapeHtml(method)}</pre>
                    </div>
                    <div class="info-item">
                        <strong>Route Path:</strong> 
                        <pre class="decoded-content" style="white-space: pre-wrap; word-break: break-all;">${escapeHtml(route)}</pre>
                    </div>
                </div>
            `;
        }
        
        /**
         * Convert internal event type to display type
         * @param {string} type - Internal event type
         * @returns {string} Display type
         */
        function getDisplayType(type) {
            if (!type) return 'Unknown';
            
            switch (type) {
                case 'Propagator':
                case 'P2O':
                case 'O2P':
                case 'P2P':
                case 'O2R':
                case 'P2R': // Added P2R to be displayed as Data Flow
                    return 'Data Flow';
                case 'Creation':
                case 'Source':
                    return 'Source';
                case 'Trigger':
                    return 'Violation';
                case 'http-request':
                    return 'HTTP Request';
                default:
                    return type;
            }
        }
    
        /**
         * Escape HTML special characters
         * @param {string} unsafe - Unsafe string
         * @returns {string} Escaped string
         */
        function escapeHtml(unsafe) {
            if (unsafe === undefined || unsafe === null) return '';
            
            return unsafe
                .toString()
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }
        
        /**
         * Decode HTML entities in a string
         * @param {string} html - String with HTML entities
         * @returns {string} Decoded string
         */
        function decodeHtml(html) {
            if (html === undefined || html === null) return '';
            
            const textarea = document.createElement('textarea');
            textarea.innerHTML = html;
            return textarea.value;
        }
        
        /**
         * Set up sidebar resizing and toggling functionality
         */
        function setupSidebar() {
            const sidebar = document.querySelector('.sidebar');
            const resizer = document.getElementById('sidebar-resizer');
            const toggle = document.getElementById('sidebar-toggle');
            const container = document.querySelector('.container');
            
            if (!sidebar || !resizer || !toggle || !container) {
                console.error("Could not find necessary DOM elements for sidebar setup");
                return;
            }
            
            // Set initial sidebar width to 50% of container width
            const containerWidth = container.offsetWidth;
            const initialSidebarWidth = Math.floor(containerWidth * 0.5) - 16; // subtract margin
            sidebar.style.flexBasis = `${initialSidebarWidth}px`;
            
            // Store the original sidebar width to restore when expanding
            let originalSidebarWidth = initialSidebarWidth;
            let startX, startWidth;
            
            // Handle sidebar toggle click
            toggle.addEventListener('click', () => {
                if (sidebar.classList.contains('sidebar-collapsed')) {
                    // Expand sidebar
                    sidebar.classList.remove('sidebar-collapsed');
                    sidebar.style.flexBasis = `${originalSidebarWidth}px`;
                } else {
                    // Collapse sidebar
                    originalSidebarWidth = sidebar.offsetWidth;
                    sidebar.classList.add('sidebar-collapsed');
                }
                
                // Force redraw of the graph after sidebar toggle
                window.setTimeout(() => {
                    if (window.graphRenderer) {
                        window.graphRenderer.forceRerender = true;
                        window.graphRenderer.updateSize();
                    }
                }, 300); // Match transition time in CSS
            });
            
            // Sidebar resizing functionality
            function startResize(e) {
                startX = e.clientX;
                startWidth = sidebar.offsetWidth;
                resizer.classList.add('active');
                
                document.addEventListener('mousemove', resize);
                document.addEventListener('mouseup', stopResize);
                
                // Prevent selection during resize
                document.body.style.userSelect = 'none';
            }
            
            function resize(e) {
                const newWidth = startWidth - (e.clientX - startX);
                // Apply constraints - min 150px, max 60% of window width
                if (newWidth >= 150 && newWidth <= window.innerWidth * 0.6) {
                    sidebar.style.flexBasis = `${newWidth}px`;
                    originalSidebarWidth = newWidth;
                }
            }
            
            function stopResize() {
                resizer.classList.remove('active');
                document.removeEventListener('mousemove', resize);
                document.removeEventListener('mouseup', stopResize);
                document.body.style.userSelect = '';
                
                // Force redraw of the graph after resize
                if (window.graphRenderer) {
                    window.graphRenderer.updateSize();
                }
            }
            
            // Add resize event listener
            resizer.addEventListener('mousedown', startResize);
            
            // Store graphRenderer in window for access in toggle/resize handlers
            window.graphRenderer = graphRenderer;
        }
    } catch (initError) {
        console.error("Error initializing application:", initError);
        alert(`Failed to initialize application: ${initError.message}\nCheck that required scripts are loaded properly.`);
    }
});
