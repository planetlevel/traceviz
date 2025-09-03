/**
 * Test script to verify that the number of nodes in the graph 
 * matches the number of events in the XML file.
 */
document.addEventListener('DOMContentLoaded', () => {
    console.log("Node count test started");
    
    // Set up elements for test results display
    const resultContainer = document.createElement('div');
    resultContainer.id = 'test-results';
    resultContainer.style.backgroundColor = '#f8f9fa';
    resultContainer.style.border = '1px solid #ddd';
    resultContainer.style.borderRadius = '4px';
    resultContainer.style.padding = '15px';
    resultContainer.style.margin = '20px 0';
    resultContainer.style.fontFamily = 'monospace';
    document.querySelector('.container').prepend(resultContainer);
    
    // Add a file input for loading XML files
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.id = 'xml-file-input';
    fileInput.accept = '.xml';
    fileInput.style.display = 'none';
    resultContainer.appendChild(fileInput);
    
    // Add file selection button
    const fileButton = document.createElement('button');
    fileButton.innerText = 'Select XML File';
    fileButton.style.padding = '8px 15px';
    fileButton.style.marginRight = '10px';
    fileButton.style.backgroundColor = '#4f6bbd';
    fileButton.style.color = 'white';
    fileButton.style.border = 'none';
    fileButton.style.borderRadius = '4px';
    fileButton.style.cursor = 'pointer';
    fileButton.onclick = () => fileInput.click();
    resultContainer.appendChild(fileButton);
    
    // Add a button to run the test
    const testButton = document.createElement('button');
    testButton.innerText = 'Run Node Count Test';
    testButton.style.padding = '8px 15px';
    testButton.style.marginBottom = '10px';
    testButton.style.backgroundColor = '#4f6bbd';
    testButton.style.color = 'white';
    testButton.style.border = 'none';
    testButton.style.borderRadius = '4px';
    testButton.style.cursor = 'pointer';
    testButton.disabled = true; // Disabled until file is loaded
    resultContainer.appendChild(testButton);
    
    // Add result display elements
    const resultOutput = document.createElement('pre');
    resultOutput.style.backgroundColor = '#1e2433';
    resultOutput.style.color = '#e1e6ef';
    resultOutput.style.padding = '10px';
    resultOutput.style.borderRadius = '4px';
    resultOutput.style.overflow = 'auto';
    resultOutput.style.maxHeight = '300px';
    resultOutput.innerText = 'Select an XML file to test';
    resultContainer.appendChild(resultOutput);
    
    // Will initialize parser and renderer when needed
    let traceParser;
    let graphRenderer;
    
    // Store loaded XML content
    let loadedXmlContent = null;
    
    // Handle file selection
    fileInput.addEventListener('change', async (event) => {
        const file = event.target.files[0];
        if (!file) return;
        
        try {
            resultOutput.innerText = `Loading file: ${file.name}...`;
            loadedXmlContent = await file.text();
            resultOutput.innerText = `File loaded: ${file.name}\nSize: ${loadedXmlContent.length} bytes\n\nClick "Run Node Count Test" to analyze`;
            testButton.disabled = false;
        } catch (error) {
            resultOutput.innerText = `Error loading file: ${error.message}`;
            console.error('File loading error:', error);
        }
    });
    
    // Try to load the default file automatically
    fetch('/sample.xml')
        .then(response => {
            if (!response.ok) {
                throw new Error(`Failed to fetch sample.xml: ${response.status}`);
            }
            return response.text();
        })
        .then(xmlContent => {
            loadedXmlContent = xmlContent;
            resultOutput.innerText = `Default sample.xml loaded automatically\nSize: ${loadedXmlContent.length} bytes\n\nClick "Run Node Count Test" to analyze`;
            testButton.disabled = false;
        })
        .catch(error => {
            resultOutput.innerText = `Could not load default sample.xml: ${error.message}\n\nPlease select an XML file manually.`;
            console.warn('Could not load default sample:', error);
        });
        
    
    // Test function
    async function runNodeCountTest() {
        resultOutput.innerText = 'Running test...\n';
        
        try {
            if (!loadedXmlContent) {
                throw new Error('No XML content loaded. Please select an XML file first.');
            }
            
            resultOutput.innerText += `XML loaded, length: ${loadedXmlContent.length} characters\n`;
            
            // Initialize the parser and renderer
            traceParser = new window.TraceParser();
            graphRenderer = new window.GraphRenderer('trace-graph');
            
            const xmlContent = loadedXmlContent;
            
            // Parse the XML content
            const traceData = traceParser.parseXmlContent(xmlContent);
            
            // Count raw events from the XML document
            const eventCount = countXmlEvents(traceParser.xmlDoc);
            
            // Count nodes in the generated graph (excluding request and route nodes)
            const graphNodeCount = traceData.nodes.length - 2; // Subtract request and route nodes
            
            // Compare counts
            resultOutput.innerText += `\nEvents in XML: ${eventCount}\n`;
            resultOutput.innerText += `Nodes in graph (excluding request & route): ${graphNodeCount}\n`;
            
            if (eventCount === graphNodeCount) {
                resultOutput.innerText += `\n✅ TEST PASSED: Node count matches event count\n`;
                resultOutput.style.borderLeft = '4px solid #2ecc71';
            } else {
                resultOutput.innerText += `\n❌ TEST FAILED: Node count (${graphNodeCount}) does not match event count (${eventCount})\n`;
                resultOutput.innerText += `Difference: ${Math.abs(eventCount - graphNodeCount)}\n`;
                resultOutput.style.borderLeft = '4px solid #e05d50';
                
                // Additional debug info
                const typeBreakdown = getNodeTypeBreakdown(traceData.nodes);
                resultOutput.innerText += `\nNode type breakdown:\n${typeBreakdown}`;
            }
        } catch (error) {
            resultOutput.innerText += `\nERROR: ${error.message}\n`;
            resultOutput.style.borderLeft = '4px solid #e05d50';
            console.error('Test error:', error);
        }
    }
    
    /**
     * Count the total number of event elements in the XML document
     * @param {Document} xmlDoc - The XML document
     * @returns {number} Total event count
     */
    function countXmlEvents(xmlDoc) {
        if (!xmlDoc) {
            throw new Error('XML document not available');
        }
        
        // Get all types of events
        const propagationEvents = xmlDoc.getElementsByTagName('propagation-event');
        const methodEvents = xmlDoc.getElementsByTagName('method-event');
        const tagEvents = xmlDoc.getElementsByTagName('tag-event');
        
        // Sum up all event types
        const totalEvents = 
            (propagationEvents ? propagationEvents.length : 0) + 
            (methodEvents ? methodEvents.length : 0) + 
            (tagEvents ? tagEvents.length : 0);
            
        return totalEvents;
    }
    
    /**
     * Generate a breakdown of node types for debugging
     * @param {Array} nodes - Array of node objects
     * @returns {string} Formatted breakdown of node types
     */
    function getNodeTypeBreakdown(nodes) {
        const typeCounts = {};
        
        nodes.forEach(node => {
            if (!typeCounts[node.type]) {
                typeCounts[node.type] = 0;
            }
            typeCounts[node.type]++;
        });
        
        let result = '';
        for (const [type, count] of Object.entries(typeCounts)) {
            result += `- ${type}: ${count}\n`;
        }
        
        return result;
    }
    
    // Attach test function to button
    testButton.addEventListener('click', runNodeCountTest);
});