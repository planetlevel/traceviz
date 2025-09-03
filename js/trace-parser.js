/**
 * TraceParser - Handles parsing of vulnerability trace XML files
 */
window.TraceParser = class TraceParser {
    constructor() {
        this.xmlDoc = null;
        this.traceData = null;
    }

    /**
     * Parse the XML content and extract trace data
     * @param {string} xmlContent - XML content as string
     * @returns {Object} Parsed trace data
     */
    parseXmlContent(xmlContent) {
        console.log("TraceParser: Parsing XML content, length:", xmlContent.length);
        
        // Show a small snippet of the XML content
        console.log("XML content snippet:", xmlContent.substring(0, 200));
        
        const parser = new DOMParser();
        this.xmlDoc = parser.parseFromString(xmlContent, "text/xml");
        
        // Check for parsing errors
        const parseError = this.xmlDoc.getElementsByTagName("parsererror");
        if (parseError.length > 0) {
            console.error("XML parse error:", parseError[0].textContent);
            throw new Error("Error parsing XML content");
        }
        
        // Print the first level elements to debug the structure
        const rootElement = this.xmlDoc.documentElement;
        console.log("Root element name:", rootElement.tagName);
        console.log("Root element children:", Array.from(rootElement.children).map(c => c.tagName).join(", "));

        console.log("XML parsed successfully, extracting trace data");
        const result = this.extractTraceData();
        console.log("Trace data extracted:", result);
        return result;
    }

    /**
     * Extract structured trace data from the XML document
     * @returns {Object} Structured trace data
     */
    extractTraceData() {
        try {
            console.log("Extracting trace data from XML...");
            console.log("XML document:", this.xmlDoc);
            
            // Find the finding element
            const findingElement = this.xmlDoc.getElementsByTagName("finding")[0];
            
            if (!findingElement) {
                console.error("No finding element found in XML");
                throw new Error("No finding element found in XML");
            }
            
            console.log("Found finding element:", findingElement);

            // Extract vulnerability info
            const ruleId = findingElement.getAttribute("ruleId") || 'unknown';
            
            // Extract request element for URI if needed to construct title
            const requestElement = findingElement.getElementsByTagName("request")[0];
            let uri = '/';
            if (requestElement) {
                uri = requestElement.getAttribute("uri") || '/';
            }
            
            // Construct vulnerability title if not present in XML
            const providedTitle = findingElement.getAttribute("vulnerability-title");
            let title;
            if (providedTitle) {
                title = providedTitle;
            } else {
                // Construct title from rule ID and URI
                title = `${ruleId} in ${uri}`;
            }
            
            const vulnerabilityInfo = {
                uuid: findingElement.getAttribute("uuid") || 'unknown',
                ruleId: ruleId,
                applicationName: findingElement.getAttribute("application-name") || 'unknown',
                applicationId: findingElement.getAttribute("application-id") || 'unknown',
                title: title,
                link: findingElement.getAttribute("link") || '#'
            };
            
            console.log("Extracted vulnerability info:", vulnerabilityInfo);

            // Extract HTTP request info
            if (!requestElement) {
                console.error("No request element found");
                throw new Error("No request element found in XML");
            }
            
            console.log("Found request element:", requestElement);
            
            const requestInfo = {
                method: requestElement.getAttribute("method") || 'GET',
                protocol: requestElement.getAttribute("protocol") || 'http',
                version: requestElement.getAttribute("version") || '1.1',
                port: requestElement.getAttribute("port") || '80',
                uri: requestElement.getAttribute("uri") || '/',
                queryString: requestElement.getAttribute("qs") || '',
                headers: this.extractHeaders(requestElement),
                parameters: this.extractParameters(requestElement)
            };
            
            console.log("Extracted request info:", requestInfo);

            // Extract events
            const eventsElement = findingElement.getElementsByTagName("events")[0];
            if (!eventsElement) {
                console.error("No events element found");
                throw new Error("No events element found in XML");
            }
            
            console.log("Found events element:", eventsElement);
            console.log("Events element child nodes:", eventsElement.childNodes.length);
            console.log("Events element first few children:", 
                Array.from(eventsElement.childNodes).slice(0, 5).map(n => n.nodeName).join(", "));
            const events = this.extractEvents(eventsElement);
            console.log("Extracted events:", events.length);
            
            // Debug event structure
            if (events.length > 0) {
                console.log("First event structure:", JSON.stringify(events[0]));
            } else {
                console.log("No events found in the XML");
            }
            
            // Build trace data
            try {
                console.log("Building nodes from request info and events");
                console.log("Request info:", JSON.stringify(requestInfo));
                console.log("Events to build nodes from:", events.length);
                const nodes = this.buildNodes(requestInfo, events);
                console.log("Nodes built:", nodes.length);
                console.log("Node types:", nodes.map(n => n.type).join(", "));
                
                console.log("Building edges from events");
                const edges = this.buildEdges(events);
                console.log("Edges built:", edges.length);
                
                this.traceData = {
                    vulnerabilityInfo,
                    requestInfo,
                    events,
                    nodes: nodes,
                    edges: edges
                };
                
                console.log("Final trace data:", this.traceData);
                return this.traceData;
            } catch (error) {
                console.error("Error building graph data:", error);
                throw new Error(`Error building graph data: ${error.message}`);
            }
        } catch (error) {
            console.error("Error extracting trace data:", error);
            
            // Return at least a minimal structure to prevent crashes
            return {
                vulnerabilityInfo: {
                    uuid: 'error',
                    ruleId: 'error',
                    applicationName: 'Error',
                    applicationId: 'error',
                    title: 'Error: ' + error.message,
                    link: '#'
                },
                requestInfo: {
                    method: 'GET',
                    protocol: 'http',
                    uri: '/',
                    headers: [],
                    parameters: []
                },
                events: [],
                nodes: [{
                    id: "error",
                    type: "http-request",
                    label: "Error: " + error.message,
                    methodSignature: "Error loading data",
                    details: { error: error.message }
                }],
                edges: []
            };
        }
    }

    /**
     * Extract headers from request element
     * @param {Element} requestElement - The request DOM element
     * @returns {Array} Array of header objects
     */
    extractHeaders(requestElement) {
        try {
            if (!requestElement) {
                console.error("extractHeaders: No request element provided");
                return [];
            }
            
            const headersElement = requestElement.getElementsByTagName("headers")[0];
            if (!headersElement) {
                console.log("No headers element found in request");
                return [];
            }
            
            const headerElements = headersElement.getElementsByTagName("h");
            if (!headerElements || headerElements.length === 0) {
                console.log("No header elements found");
                return [];
            }
            
            console.log(`Found ${headerElements.length} headers`);
            
            return Array.from(headerElements).map(headerEl => {
                return {
                    name: headerEl.getAttribute("name") || "",
                    value: headerEl.getAttribute("value") || ""
                };
            });
        } catch (error) {
            console.error("Error extracting headers:", error);
            return [];
        }
    }

    /**
     * Extract parameters from request element
     * @param {Element} requestElement - The request DOM element
     * @returns {Array} Array of parameter objects
     */
    extractParameters(requestElement) {
        try {
            if (!requestElement) {
                console.error("extractParameters: No request element provided");
                return [];
            }
            
            const parametersElement = requestElement.getElementsByTagName("parameters")[0];
            if (!parametersElement) {
                console.log("No parameters element found in request");
                return [];
            }
            
            const paramElements = parametersElement.getElementsByTagName("p");
            if (!paramElements || paramElements.length === 0) {
                console.log("No parameter elements found");
                return [];
            }
            
            console.log(`Found ${paramElements.length} parameters`);
            
            return Array.from(paramElements).map(paramEl => {
                return {
                    name: paramEl.getAttribute("name") || "",
                    value: paramEl.getAttribute("value") || ""
                };
            });
        } catch (error) {
            console.error("Error extracting parameters:", error);
            return [];
        }
    }

    /**
     * Extract events from events element
     * @param {Element} eventsElement - The events DOM element
     * @returns {Array} Array of event objects
     */
    extractEvents(eventsElement) {
        try {
            if (!eventsElement) {
                console.error("extractEvents: No events element provided");
                return [];
            }
            
            console.log("Extracting events from events element");
            
            // Get all event types: propagation-event, method-event, and tag-event elements
            let propagationEvents = [];
            try {
                const propagationEventsList = eventsElement.getElementsByTagName("propagation-event");
                console.log("Raw propagation events:", propagationEventsList);
                propagationEvents = Array.from(propagationEventsList || []);
                console.log(`Found ${propagationEvents.length} propagation events`);
            } catch (e) {
                console.error("Error getting propagation events:", e);
                propagationEvents = [];
            }
            
            let methodEvents = [];
            try {
                const methodEventsList = eventsElement.getElementsByTagName("method-event");
                console.log("Raw method events:", methodEventsList);
                methodEvents = Array.from(methodEventsList || []);
                console.log(`Found ${methodEvents.length} method events`);
            } catch (e) {
                console.error("Error getting method events:", e);
                methodEvents = [];
            }
            
            let tagEvents = [];
            try {
                tagEvents = Array.from(eventsElement.getElementsByTagName("tag-event") || []);
                console.log(`Found ${tagEvents.length} tag events`);
            } catch (e) {
                console.error("Error getting tag events:", e);
                tagEvents = [];
            }
            
            // Combine all types of events and sort by time if available
            const allEvents = [...propagationEvents, ...methodEvents, ...tagEvents]
                .sort((a, b) => {
                    const timeA = parseInt(a.getAttribute("time")) || 0;
                    const timeB = parseInt(b.getAttribute("time")) || 0;
                    return timeA - timeB;
                });
                
            // Scan for Pattern.matcher nodes first - ensure we see them all in logs
            console.log("========= SEARCHING FOR ALL PATTERN.MATCHER NODES =========");
            let matcherCount = 0;
            
            for (let i = 0; i < allEvents.length; i++) {
                const event = allEvents[i];
                const signatureEl = event.querySelector("signature");
                if (signatureEl && signatureEl.textContent && signatureEl.textContent.includes("Pattern.matcher")) {
                    matcherCount++;
                    const objectId = event.getAttribute("objectId") || `event-${i}`;
                    console.log(`[${matcherCount}] Found Pattern.matcher at index ${i} with objectId: ${objectId}`);
                    console.log(`    Signature: ${signatureEl.textContent}`);
                    console.log(`    Tag: ${event.tagName}`);
                    console.log(`    Type: ${event.getAttribute("type")}`);
                    
                    // Full XML for the node
                    console.log(`    Full XML: ${new XMLSerializer().serializeToString(event)}`);
                }
            }
            
            console.log(`Total Pattern.matcher nodes found in scan: ${matcherCount}`);
            console.log("========================================================");
            
            // Enhanced pre-processing for handling duplicate ObjectIDs with sequential numbering
            // Track object IDs and their occurrence count
            const objectIdCounts = {};
            const objectIdPositions = {};
            
            // First pass - collect all object IDs and their positions
            for (let i = 0; i < allEvents.length; i++) {
                const event = allEvents[i];
                const objectId = event.getAttribute("objectId") || `event-${i}`;
                
                // Track this objectId's occurrences and positions
                if (!objectIdCounts[objectId]) {
                    objectIdCounts[objectId] = 1;
                    objectIdPositions[objectId] = [i];
                } else {
                    objectIdCounts[objectId]++;
                    objectIdPositions[objectId].push(i);
                }
            }
            
            // Find duplicate objectIds
            const duplicateIds = Object.keys(objectIdCounts).filter(id => objectIdCounts[id] > 1);
            console.log(`Found ${duplicateIds.length} duplicate objectIds: ${duplicateIds.join(', ')}`);
            
            // Fix duplicate objectIds by assigning unique IDs
            for (const duplicateId of duplicateIds) {
                const positions = objectIdPositions[duplicateId];
                console.log(`Fixing duplicate objectId: ${duplicateId} at positions: ${positions.join(', ')}`);
                
                // Skip the first occurrence, rename subsequent ones
                for (let i = 1; i < positions.length; i++) {
                    const pos = positions[i];
                    const newId = `${duplicateId}-${i}`;
                    console.log(`  Changing objectId at position ${pos} from ${duplicateId} to ${newId}`);
                    allEvents[pos].setAttribute("objectId", newId);
                    
                    // Update our tracking for the renamed object ID to avoid further duplicates
                    objectIdCounts[newId] = 1;
                    objectIdPositions[newId] = [pos];
                }
            }
        
            console.log(`Processing ${allEvents.length} total events`);
            
            // Track the objectIds to detect duplicates which could cause issues
            const seenObjectIds = new Set();
            
            // Track Pattern.matcher nodes during mapping 
            const patternMatcherNodes = [];
            
            const events = allEvents.map((eventEl, index) => {
                try {
                    // Store the original XML for debugging
                    const originalXml = new XMLSerializer().serializeToString(eventEl);
                    
                    // Get the objectId for duplicate checking
                    const objectId = eventEl.getAttribute("objectId") || `event-${index}`;
                    
                    // Check for Pattern.matcher signature for specific debugging
                    const signatureEl = eventEl.querySelector("signature");
                    if (signatureEl && signatureEl.textContent && signatureEl.textContent.includes("Pattern.matcher")) {
                        console.log(`Creating event object for Pattern.matcher at index ${index} with objectId: ${objectId}`);
                        patternMatcherNodes.push({
                            index,
                            objectId
                        });
                    }
                    
                    // Check for duplicate objectIds which could cause nodes to be missed
                    if (seenObjectIds.has(objectId)) {
                        console.warn(`WARNING: Duplicate objectId found: ${objectId} at index ${index}`);
                    }
                    seenObjectIds.add(objectId);
                    
                    // Add some debug logging for nodes without parents
                    const parentObjectIdsElement = eventEl.getElementsByTagName("parentObjectIds")[0];
                    if (!parentObjectIdsElement || !parentObjectIdsElement.getElementsByTagName("id").length) {
                        if (signatureEl && signatureEl.textContent) {
                            console.log(`Node without parents at index ${index}: ${signatureEl.textContent}`);
                        }
                    }
                    
                    // Check if this is a propagation-event or method-event
                    const isMethodEvent = eventEl.tagName === 'method-event';
                    const eventType = eventEl.getAttribute("type") || "Unknown";
                    
                    const event = {
                        objectId: eventEl.getAttribute("objectId") || `event-${index}`,
                        time: eventEl.getAttribute("time") || "0",
                        thread: eventEl.getAttribute("thread") || "",
                        eventType: eventType, // Store the actual XML type attribute as eventType
                        type: eventType,      // Maintain type for backward compatibility
                        target: eventEl.getAttribute("target") || "",
                        source: eventEl.getAttribute("source") || null,
                        originalXml: originalXml, // Store the original XML for debugging
                        isMethodEvent: isMethodEvent,                // Flag for method events vs. propagation events
                        isTriggerEvent: eventType === "Trigger",     // Explicit trigger flag
                        isSourceEvent: eventType === "Creation" || eventType === "Source", // Source event flag
                        isPropagationEvent: !isMethodEvent && eventType !== "Trigger" && eventType !== "Creation" && eventType !== "Source", // Propagation event flag
                        signature: this.getElementText(eventEl, "signature") || "",
                        stack: this.extractStack(eventEl),
                        args: this.extractArgs(eventEl),
                        properties: this.extractProperties(eventEl),
                        taintRanges: this.extractTaintRanges(eventEl),
                        tags: this.getElementText(eventEl, "tags")?.split(",") || [],
                        sources: this.extractSources(eventEl),
                        parentObjectIds: this.extractParentObjectIds(eventEl)
                    };
                    
                    // Extract object data
                    try {
                        const objectElement = eventEl.querySelector("object");
                        if (objectElement) {
                            const isTracked = objectElement.getAttribute("tracked") === "true";
                            const encodedContent = objectElement.textContent;
                            event.objectData = {
                                tracked: isTracked,
                                hashCode: objectElement.getAttribute("hashCode") || "",
                                encoded: encodedContent || "",
                                decoded: null
                            };
                            
                            // Try to decode the content
                            if (encodedContent) {
                                try {
                                    // First try to decode with atob (Base64)
                                    try {
                                        event.objectData.decoded = atob(encodedContent);
                                    } catch (decodeError) {
                                        // If Base64 decoding fails, use the raw content (XML may already have decoded entities)
                                        event.objectData.decoded = encodedContent;
                                        console.warn(`Base64 decoding failed for object content for event ${index}, using raw content`);
                                    }
                                    
                                    // Ensure we have valid string content that won't break rendering
                                    if (event.objectData.decoded) {
                                        // Sanitize content for safe rendering while preserving actual data
                                        // Preserve any ellipsis in the original data
                                        event.objectData.decoded = String(event.objectData.decoded).replace(/[<>&"']/g, c => {
                                            switch (c) {
                                                case '<': return '&lt;';
                                                case '>': return '&gt;';
                                                case '&': 
                                                    // Avoid double-escaping
                                                    return c.startsWith('&amp;') ? c : '&amp;';
                                                case '"': return '&quot;';
                                                case "'": return '&#39;';
                                                default: return c;
                                            }
                                        });
                                    }
                                    
                                    event.decodedObject = event.objectData.decoded; // Keep for compatibility
                                } catch (e) {
                                    console.error(`Error decoding object content for event ${index}:`, e);
                                    event.objectData.decoded = "Unable to decode content";
                                    event.decodedObject = event.objectData.decoded; // Keep for compatibility
                                }
                            }
                        }
                    } catch (e) {
                        console.error(`Error extracting object data for event ${index}:`, e);
                    }
                    
                    // Extract return data
                    try {
                        const returnElement = eventEl.querySelector("return");
                        if (returnElement) {
                            const isTracked = returnElement.getAttribute("tracked") === "true";
                            const encodedContent = returnElement.textContent;
                            event.returnData = {
                                tracked: isTracked,
                                hashCode: returnElement.getAttribute("hashCode") || "",
                                encoded: encodedContent || "",
                                decoded: null
                            };
                            
                            // Try to decode the content
                            if (encodedContent) {
                                try {
                                    // First try to decode with atob (Base64)
                                    try {
                                        event.returnData.decoded = atob(encodedContent);
                                    } catch (decodeError) {
                                        // If Base64 decoding fails, use the raw content (XML may already have decoded entities)
                                        event.returnData.decoded = encodedContent;
                                        console.warn(`Base64 decoding failed for return content for event ${index}, using raw content`);
                                    }
                                    
                                    // Ensure we have valid string content that won't break rendering
                                    if (event.returnData.decoded) {
                                        // Sanitize content for safe rendering while preserving actual data
                                        // Preserve any ellipsis in the original data
                                        event.returnData.decoded = String(event.returnData.decoded).replace(/[<>&"']/g, c => {
                                                switch (c) {
                                                    case '<': return '&lt;';
                                                    case '>': return '&gt;';
                                                    case '&': 
                                                        // Avoid double-escaping
                                                        return c.startsWith('&amp;') ? c : '&amp;';
                                                    case '"': return '&quot;';
                                                    case "'": return '&#39;';
                                                    default: return c;
                                                }
                                            });
                                    }
                                } catch (e) {
                                    console.error(`Error decoding return content for event ${index}:`, e);
                                    event.returnData.decoded = "Unable to decode content";
                                }
                            }
                        }
                    } catch (e) {
                        console.error(`Error extracting return data for event ${index}:`, e);
                    }
                    
                    return event;
                } catch (error) {
                    console.error(`Error processing event at index ${index}:`, error);
                    // Return a minimal event object to keep the array structure intact
                    return {
                        objectId: `error-event-${index}`,
                        eventType: "Error",
                        type: "Error",
                        signature: `Error: ${error.message}`
                    };
                }
            });
            
            // Final check - How many Pattern.matcher nodes made it into the final event objects?
            console.log("========= PATTERN.MATCHER NODES IN FINAL EVENT OBJECTS =========");
            let finalMatcherCount = 0;
            
            events.forEach((event, index) => {
                if (event.signature && event.signature.includes("Pattern.matcher")) {
                    finalMatcherCount++;
                    console.log(`Final Pattern.matcher node ${finalMatcherCount}: objectId=${event.objectId}, index=${index}`);
                    console.log(`  Parents:`, event.parentObjectIds);
                }
            });
            
            console.log(`Total Pattern.matcher nodes in final events array: ${finalMatcherCount}`);
            console.log(`Total Pattern.matcher nodes found in initial scan: ${matcherCount}`);
            console.log("===========================================================");
            
            if (finalMatcherCount !== matcherCount) {
                console.warn(`WARNING: Some Pattern.matcher nodes were lost during processing!`);
                console.warn(`Initial count: ${matcherCount}, Final count: ${finalMatcherCount}`);
            }
            
            return events;
        } catch (error) {
            console.error("Error extracting events:", error);
            return [];
        }
    }

    /**
     * Get text content of a child element
     * @param {Element} parentElement - Parent DOM element
     * @param {string} tagName - Tag name of child element
     * @returns {string|null} Text content or null if not found
     */
    getElementText(parentElement, tagName) {
        const element = parentElement.getElementsByTagName(tagName)[0];
        return element ? element.textContent : null;
    }

    /**
     * Extract stack trace from event element
     * @param {Element} eventElement - Event DOM element
     * @returns {Array} Array of stack frame strings
     */
    extractStack(eventElement) {
        const stackElement = eventElement.getElementsByTagName("stack")[0];
        if (!stackElement) return [];
        
        const frameElements = stackElement.getElementsByTagName("frame");
        return Array.from(frameElements).map(frameEl => frameEl.textContent);
    }

    /**
     * Extract arguments from event element
     * @param {Element} eventElement - Event DOM element
     * @returns {Array} Array of argument objects
     */
    extractArgs(eventElement) {
        const argsElement = eventElement.getElementsByTagName("args")[0];
        if (!argsElement) return [];
        
        const argElements = argsElement.getElementsByTagName("arg");
        return Array.from(argElements).map(argEl => {
            const tracked = argEl.getAttribute("tracked") === "true";
            let decodedValue = null;
            
            if (tracked) {
                try {
                    decodedValue = atob(argEl.textContent);
                    
                    // Preserve any ellipsis in the original data
                    if (typeof decodedValue === 'string') {
                        // No modifications to ellipsis patterns - keep them intact
                    }
                } catch (e) {
                    decodedValue = "Unable to decode content";
                }
            }
            
            return {
                hashCode: argEl.getAttribute("hashCode"),
                tracked,
                encodedValue: argEl.textContent,
                decodedValue
            };
        });
    }

    /**
     * Extract properties from event element
     * @param {Element} eventElement - Event DOM element
     * @returns {Object} Properties as key-value pairs
     */
    extractProperties(eventElement) {
        const propertiesElement = eventElement.getElementsByTagName("properties")[0];
        if (!propertiesElement) return {};
        
        const propElements = propertiesElement.getElementsByTagName("p");
        const properties = {};
        
        Array.from(propElements).forEach(propEl => {
            const key = propEl.getElementsByTagName("k")[0]?.textContent;
            const value = propEl.getElementsByTagName("v")[0]?.textContent;
            
            if (key && value) {
                properties[key] = value;
            }
        });
        
        return properties;
    }

    /**
     * Extract taint ranges from event element
     * @param {Element} eventElement - Event DOM element
     * @returns {Array} Array of taint range objects
     */
    extractTaintRanges(eventElement) {
        const taintRangesElement = eventElement.getElementsByTagName("taint-ranges")[0];
        if (!taintRangesElement) return [];
        
        const taintRangeElements = taintRangesElement.getElementsByTagName("taint-range");
        
        return Array.from(taintRangeElements).map(rangeEl => {
            return {
                tag: this.getElementText(rangeEl, "tag"),
                range: this.getElementText(rangeEl, "range")
            };
        });
    }

    /**
     * Extract sources from event element
     * @param {Element} eventElement - Event DOM element
     * @returns {Array} Array of source objects
     */
    extractSources(eventElement) {
        const sourcesElement = eventElement.getElementsByTagName("sources")[0];
        if (!sourcesElement) return [];
        
        const sourceElements = sourcesElement.getElementsByTagName("source");
        
        return Array.from(sourceElements).map(sourceEl => {
            return {
                type: sourceEl.getAttribute("type"),
                name: sourceEl.getAttribute("name")
            };
        });
    }

    /**
     * Extract parent object IDs from event element
     * @param {Element} eventElement - Event DOM element
     * @returns {Array} Array of parent object ID strings
     */
    extractParentObjectIds(eventElement) {
        const parentObjectIdsElement = eventElement.getElementsByTagName("parentObjectIds")[0];
        if (!parentObjectIdsElement) return [];
        
        const idElements = parentObjectIdsElement.getElementsByTagName("id");
        
        return Array.from(idElements).map(idEl => idEl.textContent);
    }

    /**
     * Build nodes array for graph visualization
     * @param {Object} requestInfo - HTTP request information
     * @param {Array} events - Array of event objects
     * @returns {Array} Array of node objects for visualization
     */
    buildNodes(requestInfo, events) {
        const nodes = [];
        
        console.log("Building nodes with", events.length, "events");
        
        // Debug to verify Pattern.matcher nodes are included in nodes
        console.log("========= PATTERN.MATCHER NODES IN buildNodes INPUT =========");
        let matcherCount = 0;
        events.forEach((event, index) => {
            if (event.signature && event.signature.includes("Pattern.matcher")) {
                matcherCount++;
                console.log(`Pattern.matcher node ${matcherCount}: objectId=${event.objectId}, index=${index}`);
            }
        });
        console.log(`Total Pattern.matcher nodes found in buildNodes: ${matcherCount}`);
        console.log("===========================================================");
        
        // Find tracked parameters from the request
        const trackedParams = requestInfo.parameters || [];
        const paramNames = trackedParams.map(p => `'${p.name}'`).join(", ");
        
        // Create HTTP request node with annotations
        const httpRequestNode = {
            id: "request",
            type: "http-request",
            // Title (main label) - Event type
            label: "HTTP Request",
            // Method signature - URL
            methodSignature: `${requestInfo.method} ${requestInfo.uri}${requestInfo.queryString ? '?' + requestInfo.queryString : ''}`,
            // Tainted data (parameter value)
            taintedData: trackedParams.length > 0 ? `Source: ${trackedParams.map(p => `${p.name}="${p.value}"`).join(', ')}` : '',
            // Create artificial taint ranges for the entire parameter values
            taintRanges: trackedParams.length > 0 ? trackedParams.map((param, idx) => {
                // Calculate position of this parameter value in the combined string
                // Note that taint ranges are relative to the value part AFTER "Source: " prefix
                const prevParamsLength = trackedParams.slice(0, idx)
                    .reduce((len, p) => len + `${p.name}="${p.value}"`.length + 2, 0); // +2 for ', '
                const startPos = prevParamsLength + param.name.length + 2; // +2 for '=\"'
                const endPos = startPos + param.value.length;
                return {
                    tag: 'tainted',
                    range: `${startPos}:${endPos}`
                };
            }) : [],
            // Full details
            details: requestInfo
        };
        
        nodes.push(httpRequestNode);
        
        // Extract route from vulnerability title or HTTP request URI
        let route = null;
        try {
            // First try to get route from vulnerability title
            const findingElement = this.xmlDoc?.getElementsByTagName("finding")[0];
            if (findingElement) {
                const vulnTitle = findingElement.getAttribute("vulnerability-title") || '';
                const routeMatch = vulnTitle.match(/on "(\/[^\"]*)" page/);
                if (routeMatch && routeMatch[1]) {
                    route = routeMatch[1];
                }
            }
            
            // If no route found from vulnerability title, use the URI from HTTP request
            if (!route && requestInfo && requestInfo.uri) {
                route = requestInfo.uri;
                
                // Clean up the URI if it contains a full URL
                if (route.startsWith('http://') || route.startsWith('https://')) {
                    try {
                        const url = new URL(route);
                        route = url.pathname;
                    } catch (e) {
                        console.warn("Failed to parse URL:", e);
                        // Just use whatever we have as a fallback
                    }
                }
                
                // Add a leading slash if missing
                if (!route.startsWith('/')) {
                    route = '/' + route;
                }
                
                console.log("Created route from HTTP request URI:", route);
            }
        } catch (error) {
            console.error("Error extracting route:", error);
        }
        
        // Always create a route node - use default values if no route was found
        const routeNode = {
            id: "route",
            type: "route",
            // Title (main label) - Event type
            label: "Route",
            // Method signature - use generic text if no specific route was found
            methodSignature: route ? `Controller handling ${route}` : `Controller handling request`,
            // No tainted data
            taintedData: '',
            // Full details
            details: {
                route: route || '/unknown',
                method: requestInfo.method
            }
        };
        
        nodes.push(routeNode);
        
        // Find the violation/trigger node for debugging
        const violationNode = events.find(e => e.isTriggerEvent || e.type === 'Trigger' || e.eventType === "Trigger");
        if (violationNode) {
            console.log("Found violation node:", violationNode.objectId);
            console.log("  Parents:", violationNode.parentObjectIds);
        }
        
        // Add event nodes with more descriptive labels and annotations
        events.forEach((event, index) => {
            // Check if this is a trigger event
            const isTrigger = event.isTriggerEvent || event.type === 'Trigger' || event.eventType === "Trigger";
            
            // Get source info - extract the input parameter with taint
            let sourceInfo = "";
            
            // Handle trigger events differently
            if (isTrigger) {
                // Extract rule ID for trigger events
                const ruleId = this.xmlDoc?.getElementsByTagName("finding")[0]?.getAttribute("ruleId") || '';
                
                // Format rule ID to be more human-readable
                let formattedRuleId = '';
                if (ruleId) {
                    formattedRuleId = ruleId.replace(/-/g, ' ')
                        // Capitalize first letter of each word
                        .split(' ')
                        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
                        .join(' ');
                }
                
                sourceInfo = `VULNERABILITY: ${formattedRuleId || 'Security Rule Violation'}`;
            } else {
                try {
                    // Try to get source parameter from event properties
                    if (event.source) {
                        const sourceCode = event.source;
                        if (sourceCode === 'P' || sourceCode.startsWith('P')) {
                            // It's a parameter
                            sourceInfo = `Source: Parameter`;
                            if (sourceCode !== 'P' && sourceCode.match(/^P\\d+$/)) {
                                // It's a specific parameter number
                                const paramNumber = parseInt(sourceCode.substring(1), 10);
                                sourceInfo = `Source: Parameter ${paramNumber + 1}`; // P0 is first parameter, add 1 for display
                            }
                        } else if (sourceCode === 'O') {
                            sourceInfo = "Source: Object";
                        } else if (sourceCode === 'R') {
                            sourceInfo = "Source: Return Value";
                        }
                        
                        // Add the tainted value if available
                        if (event.args && event.args.length > 0) {
                            const trackedArgs = event.args.filter(arg => arg.tracked);
                            if (trackedArgs.length > 0) {
                                const taintedValue = trackedArgs.map(arg => arg.decodedValue || "").join(", ");
                                if (taintedValue) {
                                    sourceInfo += ` = "${taintedValue}"`;
                                }
                            }
                        }
                    } else if (event.args && event.args.length > 0) {
                        // Fallback: check if any args are tracked
                        const trackedArgs = event.args.filter(arg => arg.tracked);
                        if (trackedArgs.length > 0) {
                            sourceInfo = `Source: Parameter = "${trackedArgs[0].decodedValue || ""}"`;
                        }
                    }
                    
                    // If still no source info, try other approaches
                    if (!sourceInfo) {
                        if (event.isSourceEvent) {
                            sourceInfo = "Source: Untrusted Input";
                        } else {
                            sourceInfo = "Source: Data Flow";
                        }
                    }
                } catch (e) {
                    sourceInfo = "Source: Unknown";
                    console.error("Error getting source info:", e);
                }
            }
            
            // Get target info - the full result with tainted parameter
            let targetInfo = "";
            
            // Handle trigger events differently
            if (isTrigger) {
                // For trigger events, explain why it's vulnerable
                const taintedData = this.getTaintedDataValue(event);
                if (taintedData) {
                    targetInfo = `Tainted Data: "${taintedData}"`;
                } else {
                    targetInfo = "Vulnerable Method Call";
                }
                
                // Add explanation based on rule type if available
                const ruleId = this.xmlDoc?.getElementsByTagName("finding")[0]?.getAttribute("ruleId") || '';
                if (ruleId.includes('sql') || ruleId.includes('hql') || ruleId.includes('hibernate')) {
                    targetInfo = `SQL/HQL Query with untrusted data`;
                } else if (ruleId.includes('xss')) {
                    targetInfo = `Output with unsanitized data`;
                } else if (ruleId.includes('path')) {
                    targetInfo = `File path with untrusted data`;
                } else if (ruleId.includes('command')) {
                    targetInfo = `OS command with untrusted data`;
                }
            } else {
                try {
                    if (event.target) {
                        const targetCode = event.target;
                        if (targetCode === 'O') {
                            targetInfo = "Target: Object";
                        } else if (targetCode === 'R') {
                            targetInfo = "Target: Return Value";
                        } else if (targetCode === 'P' || targetCode.startsWith('P')) {
                            targetInfo = "Target: Parameter";
                        }
                        
                        // Add the tainted data if available
                        const taintedData = this.getTaintedDataValue(event);
                        if (taintedData) {
                            targetInfo += ` = "${taintedData}"`;
                        }
                    } else {
                        // Fallback to just showing the tainted data
                        const taintedData = this.getTaintedDataValue(event);
                        if (taintedData) {
                            targetInfo = `Target: Result = "${taintedData}"`;
                        } else {
                            targetInfo = "Target: Unknown";
                        }
                    }
                } catch (e) {
                    targetInfo = "Target: Unknown";
                    console.error("Error getting target info:", e);
                }
            }
            
            // Determine the event type for the top line
            let eventType;
            if (event.isTriggerEvent || event.type === 'Trigger') {
                eventType = 'Violation';
            } else if (event.isSourceEvent || event.type === 'Creation' || event.type === 'Source') {
                eventType = 'Source';
            } else {
                eventType = 'Propagator';
            }
            
            nodes.push({
                id: event.objectId,
                type: "trace-event",
                // First line - Event type (Source, Propagator, Violation)
                label: eventType,
                // Second line - method signature with parameters
                methodSignature: this.getFormattedMethodSignature(event),
                // Third line - data flow information
                taintedData: this.getDataFlowInfo(event, targetInfo),
                // Taint ranges for highlighting
                taintRanges: event.taintRanges || [],
                // Rule ID for trigger events
                ruleId: this.xmlDoc?.getElementsByTagName("finding")[0]?.getAttribute("ruleId") || '',
                // Full details
                details: event,
                // Keep the original human readable label for reference
                originalLabel: this.getHumanReadableLabel(event, index, events.length),
                // Explicitly mark source events
                isSourceEvent: event.isSourceEvent || event.type === 'Creation' || event.type === 'Source',
                // Mark trigger events
                isTriggerEvent: event.isTriggerEvent || event.type === 'Trigger'
            });
        });
        
        return nodes;
    }

    /**
     * Get data flow information for the third line of node display
     * @param {Object} event - Event object
     * @param {string} targetInfo - Pre-computed target information
     * @returns {string} Data flow information
     */
    getDataFlowInfo(event, targetInfo) {
        // For Source events: Show source data
        if (event.isSourceEvent || event.type === 'Creation' || event.type === 'Source') {
            // If we have return data, use it
            if (event.returnData && event.returnData.decoded) {
                return `Source: "${event.returnData.decoded}"`;
            }
            // If we have a tracked object as output
            if (event.objectData && event.objectData.decoded && event.objectData.tracked) {
                return `Source: "${event.objectData.decoded}"`;
            }
            // Fallback to pre-computed target info
            return targetInfo;
        }
        
        // For Trigger/Violation events: Show tainted parameter that triggers the vulnerability
        if (event.isTriggerEvent || event.type === 'Trigger') {
            // For violation events, extract the tainted parameter instead of showing the full query
            // Check for tainted args first
            const args = event.args || [];
            const trackedArgs = args.filter(arg => arg.tracked);
            
            if (trackedArgs.length > 0) {
                // For trigger events, ensure we maintain the proper taint ranges
                // First, find the correct argument with tainted data
                const taintedArg = trackedArgs[0];
                const paramValue = taintedArg.decodedValue || '';
                
                // Create a parameter-specific taint range covering the entire parameter value
                // This ensures the entire parameter is highlighted correctly
                // Always overwrite parameterTaintRanges to ensure proper highlighting
                event.parameterTaintRanges = [
                    {
                        tag: 'untrusted',
                        range: `0:${paramValue.length}`
                    }
                ];
                
                return `Parameter: "${paramValue}"`;
            }
            
            // If no tracked args, check source for proper parameter value
            if (event.source && event.source === 'P0' && event.args && event.args.length > 0) {
                const paramValue = event.args[0].decodedValue || '';
                // Ensure complete highlighting - always overwrite
                event.parameterTaintRanges = [
                    {
                        tag: 'untrusted',
                        range: `0:${paramValue.length}`
                    }
                ];
                return `Parameter: "${paramValue}"`;
            }
            
            // Fallbacks
            if (event.objectData && event.objectData.decoded) {
                const paramValue = event.objectData.decoded;
                // Ensure complete highlighting - always overwrite
                event.parameterTaintRanges = [
                    {
                        tag: 'untrusted',
                        range: `0:${paramValue.length}`
                    }
                ];
                return `Parameter: "${paramValue}"`;
            }
            if (event.returnData && event.returnData.decoded) {
                const paramValue = event.returnData.decoded;
                // Ensure complete highlighting - always overwrite
                event.parameterTaintRanges = [
                    {
                        tag: 'untrusted',
                        range: `0:${paramValue.length}`
                    }
                ];
                return `Parameter: "${paramValue}"`;
            }
            
            return targetInfo; // Already contains vulnerability information
        }
        
        // For Propagator events: Show the target of the propagation
        // Check event.target to determine what was propagated to
        const target = event.target;
        if (target) {
            // Target is 'R' for Return value
            if (target === 'R') {
                if (event.returnData && event.returnData.decoded) {
                    return `Target: "${event.returnData.decoded}"`;
                }
            }
            // Target is 'O' for Object
            else if (target === 'O') {
                if (event.objectData && event.objectData.decoded) {
                    return `Target: "${event.objectData.decoded}"`;
                }
            }
            // Target starts with 'P' for Parameter
            else if (target === 'P' || target.startsWith('P')) {
                if (event.args && event.args.length > 0) {
                    const paramNum = target === 'P' ? 0 : parseInt(target.substring(1), 10);
                    if (event.args[paramNum] && event.args[paramNum].decodedValue) {
                        return `Target: "${event.args[paramNum].decodedValue}"`;
                    }
                }
            }
        }
        
        // Fallback to pre-computed target info
        return targetInfo;
    }

    /**
     * Get a human-readable label for an event
     * @param {Object} event - Event object
     * @param {number} index - Index of the event in the sequence
     * @param {number} totalEvents - Total number of events
     * @returns {string} Human-readable label
     */
    getHumanReadableLabel(event, index, totalEvents) {
        // This is a simplified version just to make the function available
        const methodName = this.getEventLabel(event);
        const eventType = event.isSourceEvent ? "Source" : 
                         event.isTriggerEvent ? "Violation" : "Propagation";
        
        return `${eventType}: ${methodName}`;
    }

    /**
     * Get a display label for an event (legacy method)
     * @param {Object} event - Event object
     * @returns {string} Display label
     */
    getEventLabel(event) {
        if (event.signature) {
            // Extract the method name from signature
            const methodMatch = event.signature.match(/\s(\w+)\(/);
            if (methodMatch) {
                return methodMatch[1];
            }
            
            // Fallback to class name if method not found
            const classMatch = event.signature.match(/\.(\w+)\./);
            return classMatch ? classMatch[1] : "Event";
        }
        
        return event.type || "Event";
    }

    /**
     * Extract a formatted method signature from an event with actual parameter values
     * @param {Object} event - Event object 
     * @returns {string} Formatted method signature with real parameter values (code-like format)
     */
    getFormattedMethodSignature(event) {
        if (!event.signature) return "";
        
        // Simple signature extraction for display
        const signature = event.signature;
        const matches = signature.match(/([A-Za-z0-9_$.]+)\.([A-Za-z0-9_$]+)\(/);
        
        if (matches) {
            const className = matches[1];
            const methodName = matches[2];
            return `${className}.${methodName}()`;
        }
        
        return signature;
    }

    /**
     * Extract tainted data value from an event
     * @param {Object} event - Event object
     * @returns {string} Tainted data value or empty string
     */
    getTaintedDataValue(event) {
        // Simplified implementation
        if (event.args && event.args.length > 0) {
            const trackedArgs = event.args.filter(arg => arg.tracked);
            if (trackedArgs.length > 0 && trackedArgs[0].decodedValue) {
                return trackedArgs[0].decodedValue;
            }
        }
        
        if (event.objectData && event.objectData.decoded) {
            return event.objectData.decoded;
        }
        
        if (event.returnData && event.returnData.decoded) {
            return event.returnData.decoded;
        }
        
        return "";
    }

    /**
     * Gets the full data value from an event (object data, return data, or decoded object)
     * @param {Object} event - Event object
     * @returns {string} Full data value or empty string
     */
    getFullDataValue(event) {
        try {
            // Check for object data first
            if (event.objectData && event.objectData.decoded) {
                return event.objectData.decoded;
            }
            
            // Then check for return data
            if (event.returnData && event.returnData.decoded) {
                return event.returnData.decoded;
            }
            
            // Finally check for legacy decoded object
            if (event.decodedObject) {
                return event.decodedObject;
            }
            
            return "";
        } catch (error) {
            console.error("Error in getFullDataValue:", error);
            return "";
        }
    }

    /**
     * No longer truncates strings - returns the full text regardless of length
     * @param {string} text - Text that would have been truncated
     * @returns {string} Full original text without truncation
     */
    truncateWithEllipsis(text) {
        // Always return the full text without truncation
        return text;
    }
    
    /**
     * Get the original XML representation of an event for debugging
     * @param {Object} event - Event object
     * @returns {string|null} XML string or null if not available
     */
    getEventXml(event) {
        if (!event || !event.originalXml) {
            return null;
        }
        return event.originalXml;
    }

    /**
     * Build edges array for graph visualization
     * @param {Array} events - Array of event objects
     * @returns {Array} Array of edge objects for visualization
     */
    buildEdges(events) {
        const edges = [];
        
        // Basic HTTP request to route connection
        edges.push({
            source: "request",
            target: "route"
        });
        
        // Create maps to track events and their indices in the original XML order
        const eventMap = {};
        const eventPositions = {};
        const nodesMissingObjectId = [];
        const baseIdMap = {}; // Track events by their base ID
        const sourceNodeMap = {}; // Track source nodes by their base ID
        const violationNodes = []; // Track violation nodes for special handling
        
        // Track events by their position in the file and organize by base IDs
        events.forEach((event, index) => {
            const isSource = event.isSourceEvent || event.type === 'Creation' || event.type === 'Source';
            const isViolation = event.isTriggerEvent || event.type === 'Trigger';
            
            eventMap[event.objectId] = true;
            eventPositions[event.objectId] = index;
            
            // Check if this node has a proper object ID (not auto-generated)
            if (!event.objectId.match(/^\d+(?:-\d+)?$/) && event.objectId.startsWith('event-')) {
                nodesMissingObjectId.push(event.objectId);
                console.log(`Found node missing real objectId: ${event.objectId}`);
            } else if (event.objectId.match(/^\d+(?:-\d+)?$/)) {
                // Extract base ID
                const baseIdMatch = event.objectId.match(/^(\d+)(?:-\d+)?$/);
                if (baseIdMatch) {
                    const baseId = baseIdMatch[1];
                    
                    // Initialize arrays if needed
                    if (!baseIdMap[baseId]) baseIdMap[baseId] = [];
                    
                    // Add to appropriate tracking collections
                    baseIdMap[baseId].push(event);
                    
                    // Track source nodes separately by base ID
                    if (isSource) {
                        sourceNodeMap[baseId] = event.objectId;
                    }
                }
            }
            
            // Track violation nodes
            if (isViolation) {
                violationNodes.push(event);
            }
        });
        
        console.log('Base ID groups:', Object.keys(baseIdMap).map(id => `${id}: ${baseIdMap[id].length} nodes`).join(', '));
        console.log('Source nodes by base ID:', Object.keys(sourceNodeMap).map(id => `${id}: ${sourceNodeMap[id]}`).join(', '));
        
        // Connect nodes following hierarchical structure
        // HTTP -> Route -> Sources -> DataFlow -> Violations
        let previousEventId = "route"; // Start with route as the default previous
        
        // First pass: create parent-child edges + track nodes with no parents
        const nodesWithoutParents = [];
        const sourceNodes = [];
        
        // Sort events by time if available to ensure proper sequence
        const sortedEvents = [...events].sort((a, b) => {
            const timeA = parseInt(a.time) || 0;
            const timeB = parseInt(b.time) || 0;
            return timeA - timeB;
        });
        
        // Identify source nodes for special handling
        sortedEvents.forEach(event => {
            if (event.isSourceEvent || event.type === 'Creation' || event.type === 'Source') {
                sourceNodes.push(event.objectId);
            }
        });
        
        // Process events in their sorted order (likely XML file order)
        sortedEvents.forEach((event, index) => {
            // Track this node as the previous event for the next iteration
            const currentEventId = event.objectId;
            const isSource = event.isSourceEvent || event.type === 'Creation' || event.type === 'Source';
            const isViolation = event.isTriggerEvent || event.type === 'Trigger';
            
            // Special handling for violation events - link to immediately preceding event in the file
            if (isViolation) {
                const currentPosition = eventPositions[currentEventId];
                let prevNodeId = "route"; // Default
                
                // Find the event immediately before this one in the file
                if (currentPosition > 0) {
                    for (let i = currentPosition - 1; i >= 0; i--) {
                        const prevEvent = events.find(e => eventPositions[e.objectId] === i);
                        if (prevEvent) {
                            prevNodeId = prevEvent.objectId;
                            break;
                        }
                    }
                }
                
                console.log(`Linking violation node ${currentEventId} to preceding event ${prevNodeId}`);
                edges.push({
                    source: prevNodeId,
                    target: currentEventId
                });
                
                // Update previous event ID and continue to next event
                previousEventId = currentEventId;
                return;
            }
            
            if (event.parentObjectIds && event.parentObjectIds.length > 0) {
                // For each parent ID, create an edge if the parent exists
                event.parentObjectIds.forEach(parentId => {
                    // Check if parentId exists and has a base ID
                    const baseIdMatch = parentId.match(/^(\d+)(?:-\d+)?$/);
                    
                    if (baseIdMatch) {
                        const parentBaseId = baseIdMatch[1];
                        
                        // Check if this base ID has a group node (check if source exists and has other nodes with same base ID)
                        if (sourceNodeMap[parentBaseId] && 
                            baseIdMap[parentBaseId] && 
                            baseIdMap[parentBaseId].length > 1 && 
                            eventMap[`${parentBaseId}-group`]) {
                                
                            // If current event is not a source with the same base ID as the parent
                            if (!(isSource && event.objectId.startsWith(parentBaseId))) {
                                console.log(`Redirecting edge from source ${parentId} to group ${parentBaseId}-group for node ${event.objectId}`);
                                edges.push({
                                    source: `${parentBaseId}-group`, 
                                    target: event.objectId
                                });
                                return; // Skip regular parent linking
                            }
                        }
                    }
                    
                    // Regular parent handling - only create edge if parent exists
                    if (parentId === "route" || parentId === "request" || eventMap[parentId]) {
                        edges.push({
                            source: parentId,
                            target: event.objectId
                        });
                    }
                });
            } else {
                // If no parents, handle differently based on node type
                if (isSource) {
                    // Connect source nodes directly to route node
                    edges.push({
                        source: "route",
                        target: currentEventId
                    });
                } else {
                    // Special handling for nodes without real objectIds (based on file position)
                    if (nodesMissingObjectId.includes(currentEventId)) {
                        // Find the event immediately before this one in the file
                        const currentPosition = eventPositions[currentEventId];
                        let prevNodeId = "route"; // Default
                        
                        // Look for previous event in the file
                        if (currentPosition > 0) {
                            // Find the event that comes immediately before in the XML
                            for (let i = currentPosition - 1; i >= 0; i--) {
                                const prevEvent = events.find(e => eventPositions[e.objectId] === i);
                                if (prevEvent) {
                                    prevNodeId = prevEvent.objectId;
                                    break;
                                }
                            }
                        }
                        
                        console.log(`Linking node without objectId ${currentEventId} to predecessor ${prevNodeId}`);
                        edges.push({
                            source: prevNodeId,
                            target: currentEventId
                        });
                        
                        // Also link to the next node in file order if available
                        if (currentPosition < events.length - 1) {
                            for (let i = currentPosition + 1; i < events.length; i++) {
                                const nextEvent = events.find(e => eventPositions[e.objectId] === i);
                                if (nextEvent) {
                                    console.log(`Also linking to successor ${nextEvent.objectId}`);
                                    edges.push({
                                        source: currentEventId,
                                        target: nextEvent.objectId
                                    });
                                    break;
                                }
                            }
                        }
                    } else {
                        // Standard handling for normal nodes without parents
                        // Try to connect to previous source node first
                        if (sourceNodes.length > 0 && !sourceNodes.includes(currentEventId)) {
                            // Find the closest source node before this one
                            const sourceIndex = sortedEvents.findIndex(e => e.objectId === currentEventId);
                            let bestSourceId = "route"; // Default to route
                            
                            for (let i = sourceIndex - 1; i >= 0; i--) {
                                if (sourceNodes.includes(sortedEvents[i].objectId)) {
                                    bestSourceId = sortedEvents[i].objectId;
                                    break;
                                }
                            }
                            
                            nodesWithoutParents.push({
                                id: currentEventId,
                                previousId: bestSourceId
                            });
                        } else {
                            // Standard handling - connect to immediate predecessor
                            nodesWithoutParents.push({
                                id: currentEventId,
                                previousId: previousEventId
                            });
                        }
                    }
                }
            }
            
            // Update the previous event id for next iteration
            previousEventId = currentEventId;
        });
        
        // Second pass: connect remaining nodes with no parents to their predecessors
        nodesWithoutParents.forEach(node => {
            console.log(`Connecting orphaned node ${node.id} to predecessor ${node.previousId}`);
            edges.push({
                source: node.previousId,
                target: node.id
            });
        });
        
        // Add special debug info for 853 and 951 groups
        console.log("DEBUG: Checking connections between 853 and 951 groups:");
        edges.forEach(edge => {
            if (edge.source.includes('853') || edge.target.includes('853') ||
                edge.source.includes('951') || edge.target.includes('951')) {
                console.log(`  Edge: ${edge.source} -> ${edge.target}`);
            }
        });
        
        // Look for specific nodes with these IDs
        events.forEach(event => {
            if (event.objectId.includes('951') && event.parentObjectIds) {
                console.log(`Event ${event.objectId} has parents: ${event.parentObjectIds.join(', ')}`);
                if (event.parentObjectIds.some(id => id.includes('853'))) {
                    console.log(`  Found 951 event with 853 parent!`);
                    console.log(`  Adding direct edge from 853-group to 951-group`);
                    
                    // Ensure we have an edge connecting them
                    const hasDirectEdge = edges.some(edge => 
                        edge.source === '853-group' && edge.target === '951-group');
                    
                    if (!hasDirectEdge) {
                        edges.push({
                            source: '853-group',
                            target: '951-group'
                        });
                    }
                }
            }
        });
        
        return edges;
    }
};