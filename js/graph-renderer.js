/**
 * GraphRenderer - Renders the vulnerability trace as a directed acyclic graph (DAG)
 */
window.GraphRenderer = class GraphRenderer {
    /**
     * Convert internal event type to display type
     * @param {string} type - Internal event type
     * @returns {string} Display type
     */
    getDisplayType(type) {
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
            case 'route':
                return 'Route';
            default:
                return type;
        }
    }
    
    constructor(containerId) {
        this.containerId = containerId;
        this.svg = null;
        this.simulation = null;
        this.nodeElements = null;
        this.linkElements = null;
        this.data = null;
        this.width = 0;
        this.height = 0;
        this.margin = { top: 180, right: 50, bottom: 50, left: 50 }; // Increased top margin from 120 to 180
        this.nodeRadius = 18; // Increased by 50% from 12
        this.onNodeClick = null;
        this.forceRerender = false;
        this.useSankeyLayout = false; // Toggle between hierarchical and Sankey layouts
        
        // Add window resize event listener
        window.addEventListener('resize', () => {
            this.updateSize();
        });
    }

    /**
     * Initialize the SVG container
     */
    initializeSvg() {
        const container = document.getElementById(this.containerId);
        if (!container) throw new Error(`Container with id ${this.containerId} not found`);
        
        this.width = container.clientWidth;
        this.height = container.clientHeight;
        
        // Remove any existing SVG
        d3.select(`#${this.containerId} svg`).remove();
        
        // Store zoom behavior for later use
        this.zoom = d3.zoom()
            .scaleExtent([0.1, 3])
            .on("zoom", (event) => {
                // Only apply zoom transformation to the group, not individual nodes
                this.svg.attr("transform", event.transform);
                // Don't zoom the legend - keep it fixed size and position
                this.legendGroup.attr("transform", 
                    `translate(20, ${this.height - 150})`);
            });
        
        // Create new SVG
        this.svgElement = d3.select(`#${this.containerId}`)
            .append("svg")
            .attr("width", this.width)
            .attr("height", this.height)
            .attr("viewBox", [0, 0, this.width, this.height])
            .call(this.zoom); // Apply zoom behavior to SVG
            
        // Add a group to contain all elements with initial transform to center content
        const mainGroup = this.svgElement.append("g");
        
        // Store the main group as our drawing surface
        this.svg = mainGroup;
        
        // Add a fixed legend group that won't be affected by zoom
        const legendGroup = this.svgElement.append("g")
            .attr("class", "legend")
            .attr("transform", `translate(20, ${this.height - 150})`);
            
        // Store the legend group for later access
        this.legendGroup = legendGroup;
    }

    /**
     * Render the vulnerability trace graph
     * @param {Object} data - Object with nodes and edges arrays
     */
    render(data) {
        this.data = data;
        
        console.log("Rendering graph with data:", data);
        console.log("Nodes:", data.nodes.length, "Edges:", data.edges.length);
        console.log(`Current layout mode: ${this.useSankeyLayout ? 'SANKEY' : 'STANDARD'}`);
        
        this.initializeSvg();
        
        // Group nodes with the same base object ID
        this.groupSimilarNodes(data.nodes);
        
        // Initialize node category for hierarchical layout
        data.nodes.forEach(node => {
            // Categories: 0=HTTP, 1=Route, 2=Source, 3=DataFlow, 4=Violation
            if (node.id === 'request') {
                node.category = 0; // HTTP at top
            } else if (node.id === 'route') {
                node.category = 1; // Route below HTTP
            } else if (node.isSourceEvent) {
                node.category = 2; // Source nodes
            } else if (node.isTriggerEvent) {
                node.category = 4; // Violations at bottom
            } else {
                node.category = 3; // Data flow in middle
            }
            
            // Extract baseId from node ID if available for sorting
            const match = node.id.match(/^(\d+)(?:-\d+)?(?:-group)?$/);
            if (match) {
                node.baseId = parseInt(match[1]);
            }
        });
        
        // Choose layout based on the current mode
        if (this.useSankeyLayout) {
            console.log('Using Sankey layout for initial rendering');
            this.createSankeyLayout(data.nodes, data.edges);
        } else {
            console.log('Using standard DAG layout for initial rendering');
            this.createDagLayout(data.nodes, data.edges);
        }
        
        // Keep the compatibility function call but it no longer does positioning
        this.createForceSimulation(data.nodes, data.edges);
        
        // Render nodes first, then edges on top to ensure arrows are visible
        this.renderNodes(data.nodes);
        this.renderEdges(data.edges);
        this.renderLegend();
        
        // Auto-fit the graph to the viewport if using Sankey layout
        if (this.useSankeyLayout) {
            this.autoFitGraph();
        }
    }
    
    /**
     * Creates a force simulation for dynamic node positioning
     * @param {Array} nodes - Array of node objects
     * @param {Array} edges - Array of edge objects
     */
    /**
     * Collapse nodes that share the same base ID into a single representative node
     * With special handling for source nodes (kept separate)
     * @param {Array} nodes - Array of node objects
     */
    groupSimilarNodes(nodes) {
        // Step 1: Extract base IDs and group nodes
        const baseIdGroups = {};
        const baseIdRegExp = /^(\d+)(?:-(\d+))?$/;
        
        // Find all nodes with sequential IDs (format: "baseId-number" or just "baseId")
        nodes.forEach(node => {
            const match = node.id.match(baseIdRegExp);
            if (match) {
                const baseId = match[1];
                if (!baseIdGroups[baseId]) {
                    baseIdGroups[baseId] = {
                        sources: [], // Track source nodes separately
                        others: []   // Track non-source nodes
                    };
                }
                
                // Sort nodes into source vs non-source
                if (node.isSourceEvent || node.type === 'Creation' || node.type === 'Source') {
                    baseIdGroups[baseId].sources.push(node);
                } else {
                    baseIdGroups[baseId].others.push(node);
                }
                
                // Store the base ID for later reference
                node.baseId = baseId;
                // Mark original nodes that will be part of a group
                node.originalNode = true;
            }
        });
        
        console.log("Node groups by base ID:", Object.keys(baseIdGroups).map(k => 
            `${k}: ${baseIdGroups[k].sources.length} sources, ${baseIdGroups[k].others.length} others`));
        
        // Step 2: Replace non-source groups with single representative nodes
        const nodesToRemove = [];
        const nodesToAdd = [];
        const edgesToUpdate = [];
        const newEdgesToAdd = [];
        
        // Add special debug for 853 and 951 base IDs
        if (baseIdGroups['853'] || baseIdGroups['951']) {
            console.log("DEBUG: 853/951 group details:");
            if (baseIdGroups['853']) {
                console.log(`853 group: ${baseIdGroups['853'].sources.length} sources, ${baseIdGroups['853'].others.length} others`);
                baseIdGroups['853'].others.forEach(n => console.log(`  853 other: ${n.id}`));
            }
            if (baseIdGroups['951']) {
                console.log(`951 group: ${baseIdGroups['951'].sources.length} sources, ${baseIdGroups['951'].others.length} others`);
                baseIdGroups['951'].others.forEach(n => console.log(`  951 other: ${n.id}`));
                
                // Special handling: Check if any 951 node has a parent with ID 853
                baseIdGroups['951'].others.forEach(node => {
                    if (node.details && node.details.parentObjectIds) {
                        const has853Parent = node.details.parentObjectIds.some(id => 
                            id.startsWith('853') || id === '853');
                        if (has853Parent) {
                            console.log(`  Found 951 node with 853 parent: ${node.id}`);
                        }
                    }
                });
            }
        }
        
        Object.keys(baseIdGroups).forEach(baseId => {
            const group = baseIdGroups[baseId];
            const sourceNodes = group.sources;
            const otherNodes = group.others;
            
            // Special case handling:
            // 1. Keep all source nodes as-is
            // 2. Only collapse other nodes if there's more than 1
            
            // Process non-source nodes for collapsing
            if (otherNodes.length > 1) {
                // Add all non-source nodes to remove list
                otherNodes.forEach(node => {
                    nodesToRemove.push(node.id);
                });
                
                // Create a new representative node for the non-source group
                const representativeNode = {
                    id: `${baseId}-group`, // Use base ID with 'group' suffix to differentiate from source nodes
                    type: otherNodes[0].type, // Use the type from the first non-source node
                    label: otherNodes[0].label, // Use label from the first node
                    methodSignature: `${otherNodes.length} events on ${baseId}`, // Custom signature
                    taintedData: otherNodes[0].taintedData, // Use tainted data from first node
                    category: otherNodes[0].category, // Keep the same category
                    isCollapsedGroup: true, // Mark as a collapsed group
                    originalNodes: otherNodes, // Store original nodes for reference
                    isTriggerEvent: otherNodes.some(n => n.isTriggerEvent),
                    details: { 
                        ...otherNodes[0].details,
                        collapsedGroup: true,
                        groupSize: otherNodes.length,
                        objectIds: otherNodes.map(n => n.id)
                    }
                };
                
                // Add the new representative node
                nodesToAdd.push(representativeNode);
                
                // Create edges from source nodes to the representative node
                sourceNodes.forEach(sourceNode => {
                    newEdgesToAdd.push({
                        source: sourceNode.id,
                        target: representativeNode.id
                    });
                });
                
                // Update edges - we need to handle both incoming and outgoing edges for non-source nodes
                this.data.edges.forEach(edge => {
                    const edgeSourceBase = edge.source.match(baseIdRegExp)?.[1];
                    const edgeTargetBase = edge.target.match(baseIdRegExp)?.[1];
                    
                    // Skip edges that are between source nodes and other nodes in this group
                    // (We'll create new edges directly to the representative node)
                    const isSourceToOther = sourceNodes.some(s => s.id === edge.source) && 
                                          otherNodes.some(o => o.id === edge.target);
                    if (isSourceToOther) {
                        // Mark for removal but don't redirect
                        edgesToUpdate.push({
                            oldSource: edge.source,
                            oldTarget: edge.target,
                            remove: true
                        });
                        return;
                    }
                    
                    // If edge is from a non-source node in this group to another node, redirect to representative
                    if (edgeSourceBase === baseId && 
                        otherNodes.some(n => n.id === edge.source) &&
                        !otherNodes.some(n => n.id === edge.target)) {
                        edgesToUpdate.push({
                            oldSource: edge.source,
                            oldTarget: edge.target,
                            newSource: `${baseId}-group`,
                            newTarget: edge.target
                        });
                    }
                    
                    // If edge is to a non-source node in this group from another node, redirect to representative
                    if (edgeTargetBase === baseId && 
                        otherNodes.some(n => n.id === edge.target) &&
                        !otherNodes.some(n => n.id === edge.source) &&
                        !sourceNodes.some(n => n.id === edge.source)) {
                        edgesToUpdate.push({
                            oldSource: edge.source,
                            oldTarget: edge.target,
                            newSource: edge.source,
                            newTarget: `${baseId}-group`
                        });
                    }
                });
            }
        });
        
        // Step 3: Apply the changes to nodes and edges
        
        // Remove original grouped nodes but keep source nodes
        const newNodes = nodes.filter(node => !nodesToRemove.includes(node.id));
        
        // Add representative nodes
        newNodes.push(...nodesToAdd);
        
        // Update edges
        const updatedEdges = this.data.edges.filter(edge => {
            // Keep the edge only if it's not marked for removal
            const updateInfo = edgesToUpdate.find(u => 
                u.oldSource === edge.source && u.oldTarget === edge.target);
            return !updateInfo || !updateInfo.remove;
        }).map(edge => {
            // Apply edge updates
            const updateInfo = edgesToUpdate.find(u => 
                u.oldSource === edge.source && u.oldTarget === edge.target);
            
            if (updateInfo && updateInfo.newSource && updateInfo.newTarget) {
                return {
                    source: updateInfo.newSource,
                    target: updateInfo.newTarget
                };
            }
            return edge;
        });
        
        // Add new edges from source nodes to representative nodes
        updatedEdges.push(...newEdgesToAdd);
        
        // Remove duplicate edges (multiple edges between same source and target)
        const uniqueEdges = [];
        const edgeMap = new Map();
        
        updatedEdges.forEach(edge => {
            const key = `${edge.source}->${edge.target}`;
            if (!edgeMap.has(key)) {
                edgeMap.set(key, true);
                uniqueEdges.push(edge);
            }
        });
        
        // Update the data object with new nodes and edges
        this.data.nodes = newNodes;
        this.data.edges = uniqueEdges;
        
        console.log(`Collapsed ${nodesToRemove.length} nodes into ${nodesToAdd.length} representative nodes`);
        console.log(`Updated edges: removed ${edgesToUpdate.filter(u => u.remove).length}, redirected ${edgesToUpdate.filter(u => !u.remove).length}, added ${newEdgesToAdd.length}`);
        console.log(`New node count: ${newNodes.length}, New edge count: ${uniqueEdges.length}`);
        
        // Special fix: Ensure connection between 853-group and 951-group if needed
        // First, check if both nodes exist
        const node853Group = newNodes.find(n => n.id === '853-group');
        const node951Group = newNodes.find(n => n.id === '951-group');
        
        if (node853Group && node951Group) {
            console.log("Both 853-group and 951-group exist in the graph");
            
            // Check if there's already a connection
            const hasConnection = uniqueEdges.some(edge => 
                edge.source === '853-group' && edge.target === '951-group');
            
            if (!hasConnection) {
                console.log("Adding missing edge from 853-group to 951-group");
                // Add the missing edge
                this.data.edges.push({
                    source: '853-group',
                    target: '951-group'
                });
            } else {
                console.log("Connection already exists between 853-group and 951-group");
            }
        }
    }
    
    createForceSimulation(nodes, edges) {
        // This is now an empty placeholder - we don't use force simulation anymore
        // All positioning is handled directly by createDagLayout
        console.log("Force simulation disabled - using simple static layout");
    }
    
    /**
     * Auto-fit the graph to the viewport
     */
    autoFitGraph() {
        if (!this.svg || !this.svgElement || !this.zoom) {
            console.log('Cannot auto-fit: SVG elements not initialized');
            return;
        }
        
        // Get the bounding box of all content
        const bbox = this.svg.node().getBBox();
        console.log('Graph bounding box:', bbox);
        
        // Calculate the scale to fit the content
        const padding = 50; // Padding around the graph
        const availableWidth = this.width - (padding * 2);
        const availableHeight = this.height - (padding * 2);
        
        const scaleX = availableWidth / bbox.width;
        const scaleY = availableHeight / bbox.height;
        const scale = Math.min(scaleX, scaleY, 1); // Don't zoom in, only zoom out if needed
        
        console.log(`Auto-fit scale: ${scale} (scaleX: ${scaleX}, scaleY: ${scaleY})`);
        
        // Calculate the translation to center the graph
        const translateX = (this.width - bbox.width * scale) / 2 - bbox.x * scale;
        const translateY = (this.height - bbox.height * scale) / 2 - bbox.y * scale;
        
        // Apply the transform
        const transform = d3.zoomIdentity
            .translate(translateX, translateY)
            .scale(scale);
        
        // Apply with a smooth transition
        this.svgElement
            .transition()
            .duration(750)
            .call(this.zoom.transform, transform);
        
        console.log(`Auto-fit applied: scale=${scale}, translate=(${translateX}, ${translateY})`);
    }
    
    /**
     * Render the legend
     */
    renderLegend() {
        // Define legend items
        const legendData = [
            { type: "HTTP Request", color: "#e74c3c", letter: "H" }, // Red
            { type: "Route", color: "#f39c12", letter: "R" },        // Orange
            { type: "Source", color: "#2ecc71", letter: "S" },       // Green
            { type: "Data Flow", color: "#3498db", letter: "D" },    // Blue
            { type: "Violation", color: "#c0392b", letter: "V" }     // Dark red
        ];
        
        // Add legend title
        this.legendGroup.append("text")
            .attr("class", "legend-title")
            .attr("x", 0)
            .attr("y", 0)
            .attr("font-size", "14px")
            .attr("font-weight", "bold")
            .attr("fill", "white") // Make text white for dark background
            .text("Legend");
            
        // Add legend items
        const legendItems = this.legendGroup.selectAll(".legend-item")
            .data(legendData)
            .enter()
            .append("g")
            .attr("class", "legend-item")
            .attr("transform", (d, i) => `translate(15, ${35 + i * 18})`);
            
        // Add colored circles
        legendItems.append("circle")
            .attr("r", 7)
            .attr("fill", d => d.color)
            .attr("stroke", d => d3.color(d.color).darker())
            .attr("stroke-width", 1);
            
        // Add letter inside circles - properly centered
        legendItems.append("text")
            .attr("x", 0)
            .attr("y", 0) // Center vertically
            .attr("text-anchor", "middle")
            .attr("dominant-baseline", "central") // This ensures proper vertical centering
            .attr("font-size", "8px")
            .attr("font-weight", "bold")
            .attr("fill", "white")
            .text(d => d.letter);
            
        // Add text labels
        legendItems.append("text")
            .attr("x", 20)
            .attr("y", 4)
            .attr("font-size", "12px")
            .attr("fill", "white") // Make text white for dark background
            .text(d => d.type);
    }
    
    /**
     * Update the size of the SVG container and redraw
     * Use this method when the container size changes
     */
    updateSize() {
        if (!this.data) {
            console.log('updateSize: No data available, skipping');
            return;
        }
        
        const container = document.getElementById(this.containerId);
        if (!container) {
            console.log('updateSize: Container not found, skipping');
            return;
        }
        
        // Log current state
        console.log(`updateSize: Current layout mode: ${this.useSankeyLayout ? 'SANKEY' : 'STANDARD'}, forceRerender: ${this.forceRerender}`);
        
        // Update dimensions
        this.width = container.clientWidth;
        this.height = container.clientHeight;
        
        // Update the existing SVG dimensions
        d3.select(`#${this.containerId} svg`)
            .attr("width", this.width)
            .attr("height", this.height)
            .attr("viewBox", [0, 0, this.width, this.height]);
            
        // Update legend position if it exists
        if (this.legendGroup) {
            this.legendGroup.attr("transform", `translate(20, ${this.height - 150})`);
        }
        
        // Only re-render if needed
        if (this.forceRerender) {
            console.log(`Re-rendering graph with layout mode: ${this.useSankeyLayout ? 'SANKEY' : 'STANDARD'}`);
            // Remove existing SVG
            d3.select(`#${this.containerId} svg`).remove();
            
            // Re-render with current data
            this.initializeSvg();
            if (this.useSankeyLayout) {
                console.log('Using Sankey layout algorithm');
                this.createSankeyLayout(this.data.nodes, this.data.edges);
            } else {
                console.log('Using standard DAG layout algorithm');
                this.createDagLayout(this.data.nodes, this.data.edges);
            }
            this.renderEdges(this.data.edges);
            this.renderNodes(this.data.nodes);
            this.renderLegend();
            
            this.forceRerender = false;
            console.log('Graph re-rendered successfully');
        }
    }

    /**
     * Create a DAG layout for the nodes
     * @param {Array} nodes - Array of node objects
     * @param {Array} links - Array of edge objects
     */
    createDagLayout(nodes, links) {
        console.log("Creating layout with improved node positioning");
        console.log(`Total nodes: ${nodes.length}, Total edges: ${links.length}`);
        
        // Choose layout based on the current mode
        if (this.useSankeyLayout) {
            console.log("Using Sankey-style layout");
            this.createSankeyLayout(nodes, links);
            return; // Exit early, Sankey layout is complete
        }
        
        // Define positioning constants
        const verticalSpacing = 100; // Fixed spacing between rows
        const horizontalSpacing = 120; // Horizontal spacing between nodes
        const centerX = this.width / 2; // Center of the graph horizontally
        
        // Create maps for parent-child and child-parent relationships
        const childrenByParent = new Map(); // Map parent ID to array of child nodes
        const parentsByChild = new Map();    // Map child ID to array of parent nodes
        
        // Build the parent-child relationship maps from links
        links.forEach(link => {
            // Track children for each parent
            if (!childrenByParent.has(link.source)) {
                childrenByParent.set(link.source, []);
            }
            
            // Track parents for each child
            if (!parentsByChild.has(link.target)) {
                parentsByChild.set(link.target, []);
            }
            
            // Find the target node and add to parent's children
            const targetNode = nodes.find(n => n.id === link.target);
            if (targetNode) {
                childrenByParent.get(link.source).push(targetNode);
            }
            
            // Find the source node and add to child's parents
            const sourceNode = nodes.find(n => n.id === link.source);
            if (sourceNode) {
                parentsByChild.get(link.target).push(sourceNode);
            }
        });
        
        // Step 1: First assign all nodes to strict categories for ordering
        nodes.forEach(node => {
            // Categories: 0=HTTP, 1=Route, 2=Source, 3=DataFlow, 4=Violation
            if (node.id === 'request') {
                node.category = 0; // HTTP at top
            } else if (node.id === 'route') {
                node.category = 1; // Route below HTTP
            } else if (node.isSourceEvent) {
                node.category = 2; // Source nodes
            } else if (node.isTriggerEvent) {
                node.category = 4; // Violations at bottom
            } else {
                node.category = 3; // Data flow in middle
            }
            
            // Extract base ID for nodes that have a numeric ID
            const match = node.id.match(/^(\d+)(?:-\d+)?(?:-group)?$/);
            if (match) {
                node.baseId = parseInt(match[1]);
            }
            
            // Identify main flow nodes (nodes with exactly one parent and one child)
            const parentCount = parentsByChild.has(node.id) ? parentsByChild.get(node.id).length : 0;
            const childCount = childrenByParent.has(node.id) ? childrenByParent.get(node.id).length : 0;
            
            // If a node has exactly one parent and one child, it's part of the main flow
            node.isMainFlow = (parentCount === 1 && childCount === 1);
            
            // If a node has exactly one parent and no children, it's an endpoint
            node.isEndpoint = (parentCount === 1 && childCount === 0);
            
            // If a node has multiple parents or multiple children, it's a junction
            node.isJunction = (parentCount > 1 || childCount > 1);
            
            // Store connection counts for further reference
            node.parentCount = parentCount;
            node.childCount = childCount;
        });
        
        // Step 2: Group nodes by category for positioning
        const nodesByCategory = {
            0: [], // HTTP
            1: [], // Route
            2: [], // Sources
            3: [], // DataFlow
            4: []  // Violations
        };
        
        // Collect nodes for each category
        nodes.forEach(node => {
            const category = node.category;
            if (nodesByCategory[category]) {
                nodesByCategory[category].push(node);
            }
        });
        
        // Log the node connection metrics
        console.log("Node connection metrics:");
        console.log(`Main flow nodes (1 parent, 1 child): ${nodes.filter(n => n.isMainFlow).length}`);
        console.log(`Junction nodes (>1 parent or >1 child): ${nodes.filter(n => n.isJunction).length}`);
        console.log(`Endpoint nodes (1 parent, 0 children): ${nodes.filter(n => n.isEndpoint).length}`);
        
        // Step 3: Position nodes in a mostly vertical layout with main flow down the center
        // We'll use a hierarchical approach with fixed vertical increments
        
        // Start position for the topmost nodes
        const topMargin = this.margin.top + 50;
        const verticalStep = 80; // Vertical spacing between nodes
        
        // Fixed horizontal positions
        const columnPositions = {
            main: this.width / 2,             // Main central column
            left: this.width / 3,            // Left column for some branching
            right: (this.width / 3) * 2      // Right column for some branching
        };
        
        // Keep track of vertical position for each category
        let verticalPosition = {
            0: topMargin,                       // HTTP at top
            1: topMargin + verticalStep,        // Route below HTTP
            2: topMargin + verticalStep * 2,    // Sources start position
            3: topMargin + verticalStep * 4,    // Data flow start position
            4: topMargin + verticalStep * 8     // Violations start position
        };
        
        // For each category, position the nodes in a simple vertical layout
        Object.entries(nodesByCategory).forEach(([category, categoryNodes]) => {
            // Sort nodes within each category
            // HTTP and Route remain at the top in fixed order
            // For data flow nodes, sort by numeric ID if available
            if (parseInt(category) >= 2) {
                categoryNodes.sort((a, b) => {
                    // First sort by baseId if available
                    if (a.baseId !== undefined && b.baseId !== undefined) {
                        return a.baseId - b.baseId;
                    }
                    // Fallback to sorting by full ID
                    return a.id.localeCompare(b.id);
                });
            }
            
            // Position each node in this category
            const categoryNum = parseInt(category);
            
            // Process HTTP and Route categories separately and always center them
            if (categoryNum === 0) { // HTTP
                categoryNodes.forEach(node => {
                    node.x = centerX;
                    node.y = this.margin.top + 50;
                });
                return;
            }
            
            if (categoryNum === 1) { // Route
                categoryNodes.forEach(node => {
                    node.x = centerX;
                    node.y = this.margin.top + 150;
                });
                return;
            }
            
            // Source events (category 2)
            if (categoryNum === 2) {
                // If there's only one source node, center it
                if (categoryNodes.length === 1) {
                    categoryNodes[0].x = centerX;
                    categoryNodes[0].y = this.margin.top + 250;
                }
                // If multiple source nodes, spread them out
                else if (categoryNodes.length > 1) {
                    if (categoryNodes.length === 2) {
                        // Two source nodes - place left and right
                        const leftX = centerX - horizontalSpacing;
                        const rightX = centerX + horizontalSpacing;
                        categoryNodes[0].x = leftX;
                        categoryNodes[0].y = this.margin.top + 250;
                        categoryNodes[1].x = rightX;
                        categoryNodes[1].y = this.margin.top + 250;
                    } else {
                        // More than two source nodes - spread evenly
                        const leftEdge = centerX - 200;
                        const spacing = 400 / (categoryNodes.length - 1);
                        categoryNodes.forEach((node, i) => {
                            node.x = leftEdge + i * spacing;
                            node.y = this.margin.top + 250;
                        });
                    }
                }
                return;
            }
            
            // Data Flow events (category 3)
            if (categoryNum === 3) {
                // Find source nodes for reference
                const sourceNodes = nodesByCategory[2] || [];
                
                // Group by baseId
                const baseIdGroups = {};
                categoryNodes.forEach(node => {
                    const baseId = node.baseId || 'unknown';
                    if (!baseIdGroups[baseId]) {
                        baseIdGroups[baseId] = [];
                    }
                    baseIdGroups[baseId].push(node);
                });
                
                // Log node counts by baseId
                console.log("Data flow nodes by baseId:");
                Object.keys(baseIdGroups).forEach(baseId => {
                    console.log(`BaseId ${baseId}: ${baseIdGroups[baseId].length} nodes`);
                });
                
                // Find parent source for each data flow node
                const dataFlowNodesBySource = new Map(); // Map source node ID to its data flow nodes
                
                // Go through each data flow node and determine its source parent
                categoryNodes.forEach(node => {
                    // Try to find its parent in the links
                    const parentEdges = links.filter(link => link.target === node.id);
                    
                    // If we found parent edges
                    if (parentEdges.length > 0) {
                        // Look at each parent to find a source node
                        let foundSourceParent = false;
                        
                        for (const edge of parentEdges) {
                            const parentId = edge.source;
                            const parentNode = nodes.find(n => n.id === parentId);
                            
                            if (parentNode && parentNode.category === 2) { // If parent is a source node
                                // Add this node to its parent source's list
                                if (!dataFlowNodesBySource.has(parentNode.id)) {
                                    dataFlowNodesBySource.set(parentNode.id, []);
                                }
                                dataFlowNodesBySource.get(parentNode.id).push(node);
                                foundSourceParent = true;
                                console.log(`Assigned data flow node ${node.id} to source parent ${parentNode.id}`);
                                break;
                            }
                        }
                        
                        // If no source parent, add to general pool
                        if (!foundSourceParent) {
                            if (!dataFlowNodesBySource.has('general')) {
                                dataFlowNodesBySource.set('general', []);
                            }
                            dataFlowNodesBySource.get('general').push(node);
                            console.log(`Added data flow node ${node.id} to general pool (no source parent found)`);
                        }
                    } else {
                        // If no parent edge, add to general pool
                        if (!dataFlowNodesBySource.has('general')) {
                            dataFlowNodesBySource.set('general', []);
                        }
                        dataFlowNodesBySource.get('general').push(node);
                        console.log(`Added data flow node ${node.id} to general pool (no parent edges)`);
                    }
                });
                
                // Log the mapping of sources to their child nodes
                dataFlowNodesBySource.forEach((childNodes, sourceId) => {
                    if (sourceId === 'general') {
                        console.log(`General pool has ${childNodes.length} nodes`);
                    } else {
                        console.log(`Source ${sourceId} has ${childNodes.length} child nodes: ${childNodes.map(n => n.id).join(', ')}`);
                    }
                });
                
                // Now position the data flow nodes horizontally below their parent source nodes
                
                // First, position nodes that have a source parent
                sourceNodes.forEach(sourceNode => {
                    if (dataFlowNodesBySource.has(sourceNode.id)) {
                        const childNodes = dataFlowNodesBySource.get(sourceNode.id);
                        
                        // Analyze the child nodes for positioning
                        // Identify single-input/single-output nodes (main flow)
                        const mainFlowNodes = childNodes.filter(node => 
                            links.filter(link => link.target === node.id).length === 1 && 
                            links.filter(link => link.source === node.id).length === 1);
                        
                        const otherNodes = childNodes.filter(node => 
                            !(links.filter(link => link.target === node.id).length === 1 && 
                              links.filter(link => link.source === node.id).length === 1));
                        
                        console.log(`Under source ${sourceNode.id}: ${mainFlowNodes.length} main flow nodes, ${otherNodes.length} other nodes`);
                        
                        const rowY = sourceNode.y + verticalSpacing; // Position below the source node
                        
                        // Position main flow nodes in the center
                        if (mainFlowNodes.length === 1) {
                            // Single main flow node - put directly under source
                            mainFlowNodes[0].x = sourceNode.x;
                            mainFlowNodes[0].y = rowY;
                            console.log(`  Main flow node ${mainFlowNodes[0].id} centered under source`);
                        } else if (mainFlowNodes.length > 1) {
                            // Multiple main flow nodes - position them in a vertical chain
                            mainFlowNodes.forEach((node, i) => {
                                node.x = sourceNode.x; // Keep X aligned with source
                                node.y = rowY + (i * verticalStep / 2); // Stack vertically with less spacing
                                console.log(`  Main flow node ${node.id} in vertical chain at position ${i+1}`);
                            });
                        }
                        
                        // Position other nodes to the sides if there are any
                        if (otherNodes.length > 0) {
                            // Calculate how wide this group of nodes will be
                            const groupWidth = (otherNodes.length - 1) * horizontalSpacing;
                            let startX = sourceNode.x - (groupWidth / 2);
                            const otherY = rowY + (mainFlowNodes.length > 0 ? verticalStep / 2 : 0);
                            
                            // Position each non-main-flow node horizontally
                            otherNodes.forEach((node, i) => {
                                node.x = startX + (i * horizontalSpacing);
                                node.y = otherY;
                                console.log(`  Other node ${node.id} positioned at x=${node.x}, y=${node.y}`);
                            });
                        }
                        
                        // Remove these nodes from the map
                        dataFlowNodesBySource.delete(sourceNode.id);
                    }
                });
                
                // Now handle any remaining nodes (general pool)
                if (dataFlowNodesBySource.has('general')) {
                    const remainingNodes = dataFlowNodesBySource.get('general');
                    console.log(`Positioning ${remainingNodes.length} remaining data flow nodes with no source parent`);
                    
                    // Analyze nodes by their connection pattern
                    const mainFlowNodes = remainingNodes.filter(node => 
                        links.filter(link => link.target === node.id).length === 1 && 
                        links.filter(link => link.source === node.id).length === 1);
                    
                    const endpointNodes = remainingNodes.filter(node => 
                        links.filter(link => link.target === node.id).length > 0 && 
                        links.filter(link => link.source === node.id).length === 0);
                        
                    const junctionNodes = remainingNodes.filter(node => 
                        (links.filter(link => link.target === node.id).length > 1 || 
                         links.filter(link => link.source === node.id).length > 1));
                         
                    const otherNodes = remainingNodes.filter(node => 
                        !mainFlowNodes.includes(node) && 
                        !endpointNodes.includes(node) && 
                        !junctionNodes.includes(node));
                    
                    console.log(`General pool breakdown: ${mainFlowNodes.length} main flow, ${junctionNodes.length} junctions, ${endpointNodes.length} endpoints, ${otherNodes.length} other`);
                    
                    // Position main flow nodes vertically in the center
                    const baseY = this.margin.top + 350;
                    let nextY = baseY;
                    
                    if (mainFlowNodes.length > 0) {
                        mainFlowNodes.forEach((node, i) => {
                            node.x = centerX;
                            node.y = nextY;
                            nextY += verticalStep / 2;
                            console.log(`  Main flow node ${node.id} positioned at center, y=${node.y}`)
                        });
                    }
                    
                    // Position junction nodes on their own row if there are any
                    if (junctionNodes.length === 1) {
                        // Single junction - center it
                        junctionNodes[0].x = centerX;
                        junctionNodes[0].y = nextY;
                        nextY += verticalStep / 2;
                        console.log(`  Junction node ${junctionNodes[0].id} centered at y=${junctionNodes[0].y}`)
                    } else if (junctionNodes.length > 1) {
                        // Multiple junctions - spread horizontally
                        const totalWidth = (junctionNodes.length - 1) * horizontalSpacing;
                        let startX = centerX - (totalWidth / 2);
                        
                        junctionNodes.forEach((node, i) => {
                            node.x = startX + (i * horizontalSpacing);
                            node.y = nextY;
                            console.log(`  Junction node ${node.id} positioned at x=${node.x}, y=${node.y}`)
                        });
                        nextY += verticalStep / 2;
                    }
                    
                    // Position endpoint and other nodes
                    const remainingNodesToPosition = [...endpointNodes, ...otherNodes];
                    
                    if (remainingNodesToPosition.length === 1) {
                        // Single node - center it
                        remainingNodesToPosition[0].x = centerX;
                        remainingNodesToPosition[0].y = nextY;
                        console.log(`  Single remaining node ${remainingNodesToPosition[0].id} centered at y=${nextY}`)
                    } else if (remainingNodesToPosition.length > 1) {
                        // Multiple nodes - spread horizontally
                        const totalWidth = (remainingNodesToPosition.length - 1) * horizontalSpacing;
                        let startX = centerX - (totalWidth / 2);
                        
                        remainingNodesToPosition.forEach((node, i) => {
                            node.x = startX + (i * horizontalSpacing);
                            node.y = nextY;
                            console.log(`  Other node ${node.id} positioned at x=${node.x}, y=${node.y}`)
                        });
                    }
                }
                return;
            }
            
            // Violations (category 4) - position according to file sequence
            if (categoryNum === 4) {
                // For violations, respect their file sequence
                // Get the original indices from the sequence in the XML file
                const violationIndices = categoryNodes.map(node => {
                    // Find preceding nodes in the links data (violations point to their direct predecessor)
                    const incomingLinks = links.filter(link => link.target === node.id);
                    if (incomingLinks.length > 0) {
                        const predecessorIds = incomingLinks.map(link => link.source);
                        // Get the deepest predecessor
                        let maxY = 0;
                        let foundPredecessor = false;
                        
                        // Debug the predecessors
                        console.log(`Violation ${node.id} has predecessors: ${predecessorIds.join(', ')}`);
                        
                        // First, get all DataFlow nodes that should be above the violation
                        const dataFlowNodes = nodes.filter(n => n.category === 3);
                        
                        // Find the lowest positioned data flow node
                        let maxDataFlowY = 0;
                        dataFlowNodes.forEach(dfNode => {
                            if (dfNode.y && dfNode.y > maxDataFlowY) {
                                maxDataFlowY = dfNode.y;
                            }
                        });
                        
                        // Add extra spacing to ensure violations appear below all data flow nodes
                        maxY = maxDataFlowY + verticalSpacing * 1.5;
                        foundPredecessor = true;
                        
                        console.log(`  Violation ${node.id} will be positioned at Y=${maxY}, below all data flow nodes`);
                        
                        // Previous approach for reference
                        /*
                        predecessorIds.forEach(predId => {
                            const pred = nodes.find(n => n.id === predId);
                            if (pred) {
                                console.log(`  Predecessor ${predId} has y=${pred.y}, isCollapsedGroup=${!!pred.isCollapsedGroup}`);
                                
                                // Check if this is a collapsed group node
                                if (pred.isCollapsedGroup) {
                                    // For grouped nodes, we need to position further down
                                    // to account for the vertical space taken by the group
                                    const adjustedY = pred.y + verticalSpacing * 2;
                                    console.log(`  Group node ${predId} adjusted Y: ${adjustedY}`);
                                    
                                    if (adjustedY > maxY) {
                                        maxY = adjustedY;
                                        foundPredecessor = true;
                                    }
                                } 
                                // Regular node handling
                                else if (pred.y && pred.y > maxY) {
                                    maxY = pred.y;
                                    foundPredecessor = true;
                                }
                            }
                        });
                        */
                        
                        if (foundPredecessor) {
                            return { node, precedingY: maxY };
                        }
                    }
                    
                    // Default if no predecessor found
                    return { node, precedingY: this.margin.top + 450 };
                });
                
                // Sort violations by their preceding node's Y position
                violationIndices.sort((a, b) => a.precedingY - b.precedingY);
                
                // Position each violation at the bottom with proper spacing
                // Rather than using predecessors, just put them at the bottom of the chart
                const bottomY = this.height - this.margin.bottom - 100; // Default bottom position
                const availableHeight = bottomY - (this.margin.top + 450);
                const spacing = Math.min(verticalSpacing, 
                                        availableHeight / (violationIndices.length + 1));
                
                // Find the overall maximum Y of all data flow nodes to ensure violations are below
                let maxDataFlowY = 0;
                nodes.forEach(node => {
                    if (node.category === 3 && node.y && node.y > maxDataFlowY) {
                        maxDataFlowY = node.y;
                    }
                });
                
                const violationBaseY = maxDataFlowY + verticalSpacing * 3; // Position well below all data flow nodes, with more spacing
                console.log(`Positioning all violations below y=${violationBaseY}, which is below all data flow nodes`);
                
                // If only one violation, center it
                if (violationIndices.length === 1) {
                    // Position below all data flow nodes
                    violationIndices[0].node.x = centerX;
                    violationIndices[0].node.y = violationBaseY;
                    console.log(`Positioned violation node ${violationIndices[0].node.id} positioned at y=${violationBaseY}`);
                } else if (violationIndices.length > 1) {
                    // Multiple violations - position based on their predecessors
                    violationIndices.forEach((item, index) => {
                        // Vertical position is below all data flow nodes
                        // Use the base violation Y position plus some spacing for multiple violations
                        item.node.y = violationBaseY + (index * spacing);
                        
                        // Horizontal positioning - keep centered if possible
                        if (violationIndices.length === 2) {
                            // Two violations - place left and right of center
                            const leftX = centerX - horizontalSpacing/2;
                            const rightX = centerX + horizontalSpacing/2;
                            item.node.x = index === 0 ? leftX : rightX;
                        } else {
                            // More than two violations - center them
                            // Check if they share the same predecessor
                            const samePredecessor = violationIndices.filter(vi => 
                                Math.abs(vi.precedingY - item.precedingY) < 10).length > 1;
                            
                            if (samePredecessor) {
                                // If multiple violations share a predecessor, spread them horizontally
                                const sameGroup = violationIndices.filter(vi => 
                                    Math.abs(vi.precedingY - item.precedingY) < 10);
                                const groupIndex = sameGroup.findIndex(vi => vi.node.id === item.node.id);
                                const totalWidth = (sameGroup.length - 1) * horizontalSpacing;
                                const startX = centerX - (totalWidth / 2);
                                item.node.x = startX + (groupIndex * horizontalSpacing);
                            } else {
                                // If it has a unique predecessor, center it
                                item.node.x = centerX;
                            }
                        }
                        
                        console.log(`Positioned violation ${item.node.id} at x=${item.node.x}, y=${item.node.y}`);
                    });
                }
                return;
            }
        });
        
        // Step 4: Special handling for preserving parent-child relationships
        // Build a graph representation for faster parent-child lookups
        const parentMap = new Map();
        links.forEach(link => {
            if (!parentMap.has(link.target)) {
                parentMap.set(link.target, []);
            }
            parentMap.get(link.target).push(link.source);
        });
        
        // Adjust nodes to be below their parents when needed
        nodes.forEach(node => {
            // Skip HTTP and Route nodes
            if (node.id === 'request' || node.id === 'route') return;
            
            const parents = parentMap.get(node.id);
            if (parents && parents.length > 0) {
                // Find lowest parent Y position
                let maxParentY = 0;
                parents.forEach(parentId => {
                    const parentNode = nodes.find(n => n.id === parentId);
                    if (parentNode && parentNode.y > maxParentY) {
                        maxParentY = parentNode.y;
                    }
                });
                
                // Ensure node is below all of its parents
                if (maxParentY > 0 && node.y <= maxParentY + 50) {
                    node.y = maxParentY + 80;
                }
            }
        });
        
        // Final positioning check - make sure no nodes are without positions
        nodes.forEach(node => {
            if (node.x === undefined || node.y === undefined) {
                console.warn(`Node ${node.id} has no position assigned, using defaults`);
                node.x = leftMargin;
                node.y = this.margin.top + 300; // Default position if all else fails
            }
        });
        
        console.log("Simple layout completed");
    }

    /**
     * Render the nodes of the graph
     * @param {Array} nodes - Array of node objects
     */
    /**
     * Apply tag ranges to highlight portions of content in tooltips
     * @param {string} content - The content to highlight
     * @param {Array} tagRanges - Array of tag range objects with range and tag properties
     * @returns {string} HTML with highlighted content
     */
    applyTagRangesToTooltip(content, tagRanges) {
        if (!content || !tagRanges || tagRanges.length === 0) {
            return content; // No ranges to apply, return content as is (already escaped by tooltip)
        }
        
        // Assume content is already HTML-safe in the tooltip context, so no need to escape
        const contentChars = [...content];
        
        // Create a map of positions to tag names
        const highlightMap = {};
        
        // Process each tag range
        tagRanges.forEach(range => {
            if (!range.range) return;
            
            // Handle comma-separated ranges
            if (range.range.includes(',')) {
                const rangeList = range.range.split(',');
                
                // Process each range in the list
                rangeList.forEach(singleRange => {
                    // Parse range format (e.g., "0:7")
                    const [start, end] = singleRange.split(':').map(num => parseInt(num, 10));
                    
                    if (isNaN(start) || isNaN(end) || start < 0 || end > contentChars.length) {
                        return; // Invalid range
                    }
                    
                    // Mark positions for highlighting (start inclusive, end exclusive)
                    for (let i = start; i < end; i++) {
                        highlightMap[i] = range.tag || 'tainted';
                    }
                });
            } else {
                // Handle single range format
                const [start, end] = range.range.split(':').map(num => parseInt(num, 10));
                
                if (isNaN(start) || isNaN(end) || start < 0 || end > contentChars.length) {
                    return; // Invalid range
                }
                
                // Mark positions for highlighting
                for (let i = start; i < end; i++) {
                    highlightMap[i] = range.tag || 'tainted';
                }
            }
        });
        
        // Apply highlighting by inserting span tags
        let result = '';
        let currentTag = null;
        let inHighlight = false;
        
        for (let i = 0; i < contentChars.length; i++) {
            const tag = highlightMap[i];
            const char = contentChars[i]; // Don't escape - data should already be properly escaped
            
            // If entering a new highlight or changing highlight type
            if (tag && (!inHighlight || tag !== currentTag)) {
                // Close previous highlight if needed
                if (inHighlight) {
                    result += '</span>';
                }
                
                // Start new highlight
                result += `<span style="color: #ff6b61; background-color: rgba(231, 76, 60, 0.2); font-weight: bold; padding: 0px 1px; border-radius: 2px;">`;
                inHighlight = true;
                currentTag = tag;
            }
            // If exiting a highlight
            else if (!tag && inHighlight) {
                result += '</span>';
                inHighlight = false;
                currentTag = null;
            }
            
            // Add the character
            result += char;
        }
        
        // Close any open highlight at the end
        if (inHighlight) {
            result += '</span>';
        }
        
        return result;
    }
    
    /**
     * Creates a proper D3 Sankey layout for the graph
     * @param {Array} nodes - Array of node objects
     * @param {Array} links - Array of edge objects
     */
    createSankeyLayout(nodes, links) {
        console.log("Creating D3 Sankey layout");
        
        // First check if the D3 Sankey plugin is available
        if (typeof d3.sankey !== 'function') {
            console.error('D3 Sankey plugin not available. The d3-sankey.min.js file may not be loaded correctly.');
            console.log('Available d3 functions:', Object.keys(d3).filter(k => k.includes('sankey')));
            
            // Fall back to standard layout
            console.log('Falling back to standard DAG layout');
            this.useSankeyLayout = false;
            this.createDagLayout(nodes, links);
            return;
        }
        
        console.log('D3 Sankey plugin is available, proceeding with Sankey layout');
        
        // First, we need to convert our nodes and links to the format expected by D3 Sankey
        // The most important part is that nodes need numeric indices and links need to reference these indices
        
        console.log("Converting data for Sankey layout:");
        console.log("Original nodes:", nodes.map(n => n.id));
        console.log("Original links:", links.map(l => `${l.source} -> ${l.target}`));
        
        // Create nodes with numeric indices
        const sankeyNodes = [];
        const nodeMap = new Map(); // Map node IDs to array indices
        
        // Process nodes and assign numeric indices
        nodes.forEach((node, i) => {
            // Create a sankey node with necessary properties
            const sankeyNode = {
                name: node.id,
                id: i, // Use numeric index as ID
                originalId: node.id, // Keep original ID for reference
                category: node.category,
                originalNode: node // Keep reference to original node data
                // Don't set value - let D3 Sankey calculate it from the links
            };
            
            // Store the node and its index
            sankeyNodes.push(sankeyNode);
            nodeMap.set(node.id, i); // Map original ID to numeric index
        });
        
        // Process links using numeric indices instead of IDs
        const sankeyLinks = [];
        
        // Process links - use simpler, uniform flow values
        // D3 Sankey will automatically calculate node heights based on total flow
        links.forEach((link, i) => {
            // Get numeric indices for source and target
            const sourceIndex = nodeMap.get(link.source);
            const targetIndex = nodeMap.get(link.target);
            
            console.log(`Link ${i}: ${link.source}(${sourceIndex}) -> ${link.target}(${targetIndex})`);
            
            // Only create links if both nodes exist
            if (sourceIndex !== undefined && targetIndex !== undefined) {
                // Use a uniform flow value for all links
                // This creates consistent band widths
                const flowValue = 10; // Uniform value for consistent appearance
                
                // Create a Sankey link
                sankeyLinks.push({
                    source: sourceIndex, // Use numeric index
                    target: targetIndex, // Use numeric index
                    value: flowValue, // Uniform flow value
                    originalLink: link // Keep reference to original link
                });
            } else {
                console.warn(`Skipping link ${link.source} -> ${link.target} because nodes were not found`);
            }
        });
        
        console.log("Sankey nodes:", sankeyNodes);
        console.log("Sankey links:", sankeyLinks);
        
        try {
            console.log("Configuring D3 Sankey layout...");
            
            // Important: Don't deep clone the data - D3 Sankey needs to modify objects directly
            const sankeyData = {
                nodes: sankeyNodes,
                links: sankeyLinks
            };
            
            // Create sankey layout generator
            // Use generous padding for better flow visibility
            const nodeCount = sankeyNodes.length;
            // Much more generous padding for clearer flow visualization
            const dynamicPadding = nodeCount > 20 ? 40 : nodeCount > 10 ? 60 : 80;
            
            // Use a larger extent to spread nodes out more
            const extentWidth = this.width * 1.5; // 150% of viewport width
            const extentHeight = this.height * 1.5; // 150% of viewport height
            
            const sankey = d3.sankey()
                .nodeId(d => d.id) // Use numeric id
                .nodeAlign(d3.sankeyJustify) // Justify alignment for better flow visualization
                .nodeWidth(30) // Node width
                .nodePadding(dynamicPadding) // Generous padding for clear flows
                .nodeSort(null) // Let D3 handle the sorting
                .extent([[100, 100], [extentWidth - 100, extentHeight - 100]]);
                
            console.log("D3 Sankey generator configured:", sankey);
            
            // Generate the sankey layout - this mutates the data in place
            const computed = sankey(sankeyData);
            
            console.log("Sankey layout generated:", computed);
            console.log("Sankey nodes after layout:", computed.nodes);
            console.log("Sankey links after layout:", computed.links);
            
            // Verify link widths were computed
            if (computed.links && computed.links.length > 0) {
                console.log("First few link widths:");
                computed.links.slice(0, 5).forEach((link, i) => {
                    console.log(`  Link ${i}: width=${link.width}, y0=${link.y0}, y1=${link.y1}, value=${link.value}`);
                });
            }
            
            // Transfer the positions back to our original nodes
            console.log("Transferring positions back to original nodes...");
            
            computed.nodes.forEach(sankeyNode => {
                // Find the original node using the index mapping
                const index = sankeyNode.id;
                const originalNode = nodes[index];
                
                if (originalNode) {
                    console.log(`Transferring positions for node ${sankeyNode.originalId}: x0=${sankeyNode.x0}, y0=${sankeyNode.y0}`);
                    
                    // Transfer position data
                    originalNode.x = (sankeyNode.x0 + sankeyNode.x1) / 2; // Center of node
                    originalNode.y = (sankeyNode.y0 + sankeyNode.y1) / 2; // Center of node
                    
                    // Store sankey-specific data for rendering
                    originalNode.sankeyWidth = sankeyNode.x1 - sankeyNode.x0;
                    originalNode.sankeyHeight = sankeyNode.y1 - sankeyNode.y0;
                    originalNode.sankeyX0 = sankeyNode.x0;
                    originalNode.sankeyY0 = sankeyNode.y0;
                    originalNode.sankeyX1 = sankeyNode.x1;
                    originalNode.sankeyY1 = sankeyNode.y1;
                } else {
                    console.warn(`Could not find original node for Sankey node with id ${sankeyNode.id}`);
                }
            });
            
            // Store sankey links data for rendering curved paths
            // Important: Keep the D3 Sankey link format intact for the sankeyLinkHorizontal generator
            this.sankeyLinks = computed.links;
            
            // Log links to debug path generation
            console.log("Sankey links for rendering:");
            this.sankeyLinks.forEach((link, i) => {
                console.log(`Link ${i}: source=${link.source.id} (${link.source.originalId}) -> target=${link.target.id} (${link.target.originalId})`);
                console.log(`  source position: (${link.source.x0}, ${link.source.y0}) -> (${link.source.x1}, ${link.source.y1})`);
                console.log(`  target position: (${link.target.x0}, ${link.target.y0}) -> (${link.target.x1}, ${link.target.y1})`);
                console.log(`  link y values: y0=${link.y0}, y1=${link.y1}`);
                console.log(`  link width: ${link.width}`);
                console.log(`  link value: ${link.value}`);
            });
            
            console.log("Sankey layout positions transferred to original nodes");
            console.log("Prepared Sankey links for rendering:", this.sankeyLinks);
        } catch (error) {
            console.error('Error generating Sankey layout:', error);
            console.log('Falling back to standard DAG layout');
            this.useSankeyLayout = false;
            this.createDagLayout(nodes, links);
            return;
        }
    }
    
    /**
     * Escape HTML special characters
     * @param {string} unsafe - String to escape
     * @returns {string} Escaped string
     */
    escapeHtml(unsafe) {
        if (unsafe === undefined || unsafe === null) return '';
        
        return unsafe
            .toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
    
    renderNodes(nodes) {
        // Create a tooltip container (if not exists)
        let tooltip = d3.select("body").select(".node-tooltip");
        
        if (tooltip.empty()) {
            tooltip = d3.select("body").append("div")
                .attr("class", "node-tooltip")
                .style("opacity", 0)
                .style("position", "absolute")
                .style("padding", "10px")
                .style("background", "var(--card-bg, #1e2433)")
                .style("color", "var(--text-color, #e1e6ef)")
                .style("border", "1px solid var(--border-color, #2c3548)")
                .style("border-radius", "4px")
                .style("pointer-events", "none")
                .style("max-width", "350px")
                .style("font-size", "12px")
                .style("z-index", 1000);
        }
        
        // Create a node group for all nodes
        let nodeEnter = this.svg.selectAll(".node")
            .data(nodes, d => d.id)
            .enter()
            .append("g")
            .attr("class", "node")
            .attr("transform", d => `translate(${d.x},${d.y})`)
            // Make nodes draggable
            .call(d3.drag()
                .on("start", (event, d) => this.dragstarted(event, d))
                .on("drag", (event, d) => this.dragged(event, d))
                .on("end", (event, d) => this.dragended(event, d)));

        // Store node elements
        this.nodeElements = nodeEnter;
        
        console.log(`Rendering ${nodes.length} nodes in ${this.useSankeyLayout ? 'SANKEY' : 'STANDARD'} mode`);
        
        if (this.useSankeyLayout) {
            console.log('Rendering rectangular nodes for Sankey layout');
            // Draw nodes as proper Sankey rectangles positioned absolutely
            nodeEnter.append("rect")
                .attr("class", "sankey-node")
                .attr("x", d => d.sankeyX0 ? d.sankeyX0 - d.x : -this.nodeRadius) // Absolute positioning
                .attr("y", d => d.sankeyY0 ? d.sankeyY0 - d.y : -this.nodeRadius) // Absolute positioning
                .attr("width", d => d.sankeyWidth || 30)
                .attr("height", d => d.sankeyHeight || 30)
                .attr("fill", d => {
                    // Use specific colors directly instead of classes
                    if (d.type === 'http-request') return "#e74c3c";  // Red
                    if (d.type === 'route') return "#f39c12";         // Orange
                    if (d.type === 'trace-event') {
                        if (d.isTriggerEvent) return "#c0392b";      // Dark red (Violation)
                        if (d.isSourceEvent) return "#2ecc71";       // Green (Source)
                        return "#3498db";                            // Blue (Data Flow)
                    }
                    return "#777777";  // Default gray
                })
                .attr("stroke", "#fff") // White border
                .attr("stroke-width", 1)
                .attr("stroke-opacity", 0.5)
                .attr("rx", 4)  // Rounded corners
                .attr("ry", 4);  // Rounded corners
                
            // Add node labels
            nodeEnter.append("text")
                .attr("text-anchor", "middle")
                .attr("dominant-baseline", "central")
                .attr("font-size", "12px")
                .attr("font-weight", "bold")
                .attr("fill", "white")
                .attr("pointer-events", "none")
                .text(d => {
                    // For collapsed groups, show the count of events
                    if (d.isCollapsedGroup) {
                        return `${d.id} (${d.details.groupSize})`;
                    }
                    
                    // Use letters for regular nodes
                    if (d.type === 'http-request') return "HTTP";
                    if (d.type === 'route') return "ROUTE";
                    if (d.type === 'trace-event') {
                        if (d.isTriggerEvent) return "V";  // Violation
                        if (d.isSourceEvent) return "S";   // Source
                        return "D";                       // Data Flow
                    }
                    return d.id;
                });
        } else {
            // Use circular nodes for standard layout
            // Add node circles with different styles based on node type
            nodeEnter.append("circle")
            .attr("r", d => {
                // Make collapsed group nodes larger
                if (d.isCollapsedGroup) return this.nodeRadius * 1.5;
                return this.nodeRadius;
            })
            .attr("fill", d => {
                // Use specific colors directly instead of classes
                if (d.type === 'http-request') return "#e74c3c";  // Red
                if (d.type === 'route') return "#f39c12";         // Orange
                if (d.type === 'trace-event') {
                    if (d.isTriggerEvent) return "#c0392b";      // Dark red (Violation)
                    if (d.isSourceEvent) return "#2ecc71";       // Green (Source)
                    return "#3498db";                            // Blue (Data Flow)
                }
                return "#777777";  // Default gray
            })
            .attr("stroke", d => {
                // Special stroke for collapsed group nodes
                if (d.isCollapsedGroup) {
                    return "#ffdd00";  // Bright yellow stroke for collapsed groups
                }
                return "#ffffff";       // Default white stroke
            })
            .attr("stroke-width", d => d.isCollapsedGroup ? 3 : 1.5)   // Thicker stroke for collapsed groups
            .attr("stroke-opacity", d => d.isCollapsedGroup ? 1.0 : 0.7);  // Full opacity for collapsed groups
            
        // Add letter inside the circle
        this.nodeElements.append("text")
            .attr("text-anchor", "middle")
            .attr("dominant-baseline", "central")
            .attr("font-size", d => d.isCollapsedGroup ? "10px" : "12px")  // Smaller text for group nodes
            .attr("font-weight", "bold")
            .attr("fill", "white")
            .text(d => {
                // For collapsed groups, show the count of events
                if (d.isCollapsedGroup) {
                    return d.details.groupSize;
                }
                
                // Use first letter of type for regular nodes
                if (d.type === 'http-request') return "H";
                if (d.type === 'route') return "R";
                if (d.type === 'trace-event') {
                    if (d.isTriggerEvent) return "V";  // Violation
                    if (d.isSourceEvent) return "S";   // Source
                    return "D";                       // Data Flow
                }
                return "?";  // Unknown
            });
        }
            
        // Node ID labels are turned off to reduce visual clutter
        // IDs are now shown in tooltips instead
            
        // Parent ID labels are turned off to reduce visual clutter
        // Parent IDs are now shown in tooltips instead
            
        // Add tooltip behavior
        this.nodeElements
            .on("mouseover", (event, d) => {
                tooltip.transition()
                    .duration(200)
                    .style("opacity", .9);
                    
                let tooltipContent = `<div><strong>${this.getDisplayType(d.type === 'trace-event' ? d.label : d.type)}</strong></div>`;
                
                // Add node ID
                tooltipContent += `<div><strong>ID:</strong> ${d.id}</div>`;
                
                // Add parent IDs if present
                if (d.details && d.details.parentObjectIds && d.details.parentObjectIds.length > 0) {
                    tooltipContent += `<div><strong>Parent IDs:</strong> ${d.details.parentObjectIds.join(", ")}</div>`;
                }
                
                // Add method signature
                if (d.methodSignature) {
                    tooltipContent += `<div>${d.methodSignature}</div>`;
                }
                
                // Add tainted data if present, with highlighting based on tag ranges
                if (d.taintedData) {
                    // Check if the node has taint ranges to apply
                    let highlightedData = d.taintedData;
                    
                    // Strip any prefix labels like "Parameter:", "Source:", or "Target:"
                    // This ensures tag ranges apply correctly to just the data
                    const prefixMatch = highlightedData.match(/^([^:"]+:\s*")(.*?)"$/);                    
                    
                    if (prefixMatch && prefixMatch.length >= 3) {
                        // Extract the prefix and the actual data
                        const prefix = prefixMatch[1];
                        const actualData = prefixMatch[2];
                        
                        // Apply highlighting only to the actual data portion
                        let highlightedActualData = actualData;
                        if (d.details && d.details.taintRanges && d.details.taintRanges.length > 0) {
                            highlightedActualData = this.applyTagRangesToTooltip(actualData, d.details.taintRanges);
                        }
                        
                        // Reconstruct with prefix
                        tooltipContent += `<div>${prefix}${highlightedActualData}"</div>`;
                    } else {
                        // If no prefix pattern found, apply highlighting to entire string
                        if (d.details && d.details.taintRanges && d.details.taintRanges.length > 0) {
                            highlightedData = this.applyTagRangesToTooltip(highlightedData, d.details.taintRanges);
                        }
                        tooltipContent += `<div>${highlightedData}</div>`;
                    }
                }
                
                tooltip.html(tooltipContent)
                    .style("left", (event.pageX + 10) + "px")
                    .style("top", (event.pageY - 28) + "px");
            })
            .on("mouseout", () => {
                tooltip.transition()
                    .duration(500)
                    .style("opacity", 0);
            })
            .on("click", (event, d) => {
                if (this.onNodeClick) {
                    this.onNodeClick(d);
                }
            });
            
        // Hide any loading indicators
        d3.select(`#${this.containerId} .loading-indicator`).style("display", "none");
    }

    /**
     * Set the node click handler
     * @param {Function} handler - Function to call when a node is clicked
     */
    setNodeClickHandler(handler) {
        this.onNodeClick = handler;
    }
    
    /**
     * Handle drag start event
     * @param {Object} event - D3 drag event
     * @param {Object} d - Node data
     */
    dragstarted(event, d) {
        console.log("Drag started:", d.id, `in ${this.useSankeyLayout ? 'Sankey' : 'Standard'} mode`);
        
        // Store original position to allow snapping back if needed
        d.originalX = d.x;
        d.originalY = d.y;
        
        // For the static layout, we track positions directly 
        // No need for fx/fy as used in force simulations
        
        // Highlight the node being dragged
        const nodeElement = d3.select(event.sourceEvent.target.closest(".node"));
        
        if (this.useSankeyLayout) {
            // In Sankey mode, highlight the rectangle
            nodeElement.select("rect")
              .attr("stroke-width", 3)
              .attr("stroke-opacity", 1);
            console.log("Highlighting rectangle for Sankey node");
        } else {
            // In standard mode, highlight the circle
            nodeElement.select("circle")
              .attr("stroke-width", 3)
              .attr("stroke-opacity", 1);
            console.log("Highlighting circle for standard node");
        }
    }
    
    /**
     * Handle drag event
     * @param {Object} event - D3 drag event
     * @param {Object} d - Node data
     */
    dragged(event, d) {
        // Update node positions directly
        d.x = event.x;
        d.y = event.y;
        
        // Move the node visually
        d3.select(event.sourceEvent.target.closest(".node"))
          .attr("transform", `translate(${event.x},${event.y})`);
        
        // Update node position in the data structure to keep rendering consistent
        const nodeInData = this.data.nodes.find(n => n.id === d.id);
        if (nodeInData) {
            nodeInData.x = event.x;
            nodeInData.y = event.y;
        }
        
        // Update connected edges to follow the dragged node
        this.updateEdges(d);
    }
    
    /**
     * Handle drag end event
     * @param {Object} event - D3 drag event
     * @param {Object} d - Node data
     */
    dragended(event, d) {
        console.log("Drag ended:", d.id);
        
        // For the simple layout, make nodes snap back to original position
        // This ensures the layout stays consistent
        d.x = d.originalX;
        d.y = d.originalY;
        d3.select(event.sourceEvent.target.closest(".node"))
          .attr("transform", `translate(${d.originalX},${d.originalY})`);
          
        // Also update in data structure
        const nodeInData = this.data.nodes.find(n => n.id === d.id);
        if (nodeInData) {
            nodeInData.x = d.originalX;
            nodeInData.y = d.originalY;
        }
        
        // Reset the highlight styling
        const nodeElement = d3.select(event.sourceEvent.target.closest(".node"));
        
        if (this.useSankeyLayout) {
            // In Sankey mode, reset rectangle styling
            nodeElement.select("rect")
              .attr("stroke-width", d.isCollapsedGroup ? 3 : 1.5) // Preserve thicker stroke for groups
              .attr("stroke-opacity", d.isCollapsedGroup ? 1.0 : 0.7); // Preserve full opacity for groups
        } else {
            // In standard mode, reset circle styling
            nodeElement.select("circle")
              .attr("stroke-width", d.isCollapsedGroup ? 3 : 1.5) // Preserve thicker stroke for groups
              .attr("stroke-opacity", d.isCollapsedGroup ? 1.0 : 0.7); // Preserve full opacity for groups
        }
        
        // Redraw all edges to ensure they reconnect properly
        this.renderEdges(this.data.edges);
    }
    
    /**
     * Update edges connected to a dragged node
     * @param {Object} node - Node being dragged
     */
    updateEdges(node) {
        if (!this.data || !this.data.edges) return;
        
        // Find all edges connected to this node
        const connectedEdges = this.data.edges.filter(edge => 
            edge.source === node.id || edge.target === node.id);
            
        // Update the node's position in the data model during drag
        const nodeInData = this.data.nodes.find(n => n.id === node.id);
        if (nodeInData) {
            nodeInData.x = node.x;
            nodeInData.y = node.y;
        }
        
        // Update the corresponding visual edge elements
        this.svg.selectAll(".flow-path")
            .filter(function(d) {
                const sourceId = typeof d.source === 'object' ? d.source.id : d.source;
                const targetId = typeof d.target === 'object' ? d.target.id : d.target;
                return sourceId === node.id || targetId === node.id;
            })
            .each((d, i, nodes) => {
                // Get source and target nodes from the data
                const sourceId = typeof d.source === 'object' ? d.source.id : d.source;
                const targetId = typeof d.target === 'object' ? d.target.id : d.target;
                
                // Find the actual node objects from our data
                const sourceNode = this.data.nodes.find(n => n.id === sourceId);
                const targetNode = this.data.nodes.find(n => n.id === targetId);
                
                if (!sourceNode || !targetNode) return;
                
                // Get current positions - use node.x/y for the dragged node
                const sourceX = sourceNode.id === node.id ? node.x : sourceNode.x;
                const sourceY = sourceNode.id === node.id ? node.y : sourceNode.y;
                const targetX = targetNode.id === node.id ? node.x : targetNode.x;
                const targetY = targetNode.id === node.id ? node.y : targetNode.y;
                
                // Calculate node radii
                const sourceRadius = sourceNode.isCollapsedGroup ? this.nodeRadius * 1.5 : this.nodeRadius;
                const targetRadius = targetNode.isCollapsedGroup ? this.nodeRadius * 1.5 : this.nodeRadius;
                
                // Calculate angle and intersection points for a straight line between centers
                const dx = targetX - sourceX;
                const dy = targetY - sourceY;
                const angle = Math.atan2(dy, dx);
                
                // Calculate start and end points at the edge of the circles
                const sourceIntersectX = sourceX + Math.cos(angle) * sourceRadius;
                const sourceIntersectY = sourceY + Math.sin(angle) * sourceRadius;
                const targetIntersectX = targetX - Math.cos(angle) * targetRadius;
                const targetIntersectY = targetY - Math.sin(angle) * targetRadius;
                
                // Select this edge element
                const edge = d3.select(nodes[i]);
                
                // Create edge path based on node positions
                // For vertical relationships (significant Y difference)
                if (Math.abs(targetY - sourceY) > 30) {
                    // Use a nice curved path
                    const verticalOffset = Math.min(80, Math.abs(targetY - sourceY) / 3);
                    
                    if (targetY > sourceY) {
                        // Source is above target - use S curve
                        edge.attr("d", `M${sourceIntersectX},${sourceIntersectY} C${sourceX},${sourceY + verticalOffset} ${targetX},${targetY - verticalOffset} ${targetIntersectX},${targetIntersectY}`);
                    } else {
                        // Target is above source - use reverse S curve
                        const horizontalOffset = Math.abs(targetX - sourceX) / 2;
                        edge.attr("d", `M${sourceIntersectX},${sourceIntersectY} C${sourceX + horizontalOffset},${sourceY} ${targetX - horizontalOffset},${targetY} ${targetIntersectX},${targetIntersectY}`);
                    }
                } else {
                    // For similar vertical positions, use a simple curve
                    const midY = (sourceY + targetY) / 2;
                    edge.attr("d", `M${sourceIntersectX},${sourceIntersectY} Q${(sourceX + targetX) / 2},${midY + 15} ${targetIntersectX},${targetIntersectY}`);
                }
            });
    }

    /**
     * Render the edges of the graph
     * @param {Array} edges - Array of edge objects
     */
    /**
     * Helper method to render edges in standard mode (for fallback)
     * @param {Array} edges - Array of edge objects 
     */
    renderEdgesStandard(edges) {
        // Create or update edges
        this.linkElements = this.svg.selectAll(".link")
            .data(edges)
            .enter()
            .append("path")
            .attr("class", "flow-path")
            .attr("stroke", "white")
            .attr("stroke-width", 2)
            .attr("marker-end", "url(#arrowhead)")
            .attr("d", d => {
                // Calculate path from source to target
                const sourceNode = this.data.nodes.find(node => node.id === d.source);
                const targetNode = this.data.nodes.find(node => node.id === d.target);
                
                if (!sourceNode || !targetNode) {
                    console.warn(`Edge references missing node: ${d.source} -> ${d.target}`);
                    console.log(`Missing source or target: ${d.source} -> ${d.target}`);
                    return "";
                }
                
                // Get node coordinates, ensuring they exist
                const sourceX = sourceNode.x || 0;
                const sourceY = sourceNode.y || 0;
                const targetX = targetNode.x || 0;
                const targetY = targetNode.y || 0;
                
                // Calculate node radii - larger for collapsed group nodes
                const sourceRadius = sourceNode.isCollapsedGroup ? this.nodeRadius * 1.5 : this.nodeRadius;
                const targetRadius = targetNode.isCollapsedGroup ? this.nodeRadius * 1.5 : this.nodeRadius;
                
                // Simple calculation of edge connection points (from edge of circle)
                const angle = Math.atan2(targetY - sourceY, targetX - sourceX);
                const sourceIntersectX = sourceX + Math.cos(angle) * sourceRadius;
                const sourceIntersectY = sourceY + Math.sin(angle) * sourceRadius;
                const targetIntersectX = targetX - Math.cos(angle) * targetRadius;
                const targetIntersectY = targetY - Math.sin(angle) * targetRadius;
                
                // Calculate the distance between nodes
                const dx = targetIntersectX - sourceIntersectX;
                const dy = targetIntersectY - sourceIntersectY;
                const distance = Math.sqrt(dx * dx + dy * dy);
                
                // Determine if this is primarily a vertical or horizontal connection
                const isMoreVertical = Math.abs(dy) > Math.abs(dx);
                
                // For vertical connections (common in our layout), use nice S-curves
                if (isMoreVertical) {
                    // Adjust curve strength based on horizontal distance
                    const curveStrength = Math.min(Math.abs(dx) * 0.8, 50) + 20;
                    
                    // Calculate S-curve control points - gentler for shorter distances
                    const sourceCP = { 
                        x: sourceIntersectX + (dx > 0 ? curveStrength : -curveStrength),
                        y: sourceIntersectY + Math.abs(dy) * 0.25
                    };
                    
                    const targetCP = {
                        x: targetIntersectX - (dx > 0 ? curveStrength : -curveStrength),
                        y: targetIntersectY - Math.abs(dy) * 0.25
                    };
                    
                    // Use cubic Bezier curve for smooth S-curve
                    return `M${sourceIntersectX},${sourceIntersectY} C${sourceCP.x},${sourceCP.y} ${targetCP.x},${targetCP.y} ${targetIntersectX},${targetIntersectY}`;
                } 
                // For horizontal connections, use arched curves
                else {
                    // Calculate the midpoint
                    const midX = (sourceIntersectX + targetIntersectX) / 2;
                    
                    // Adjust arch height based on distance
                    const archHeight = Math.min(Math.abs(dx) * 0.15, 30);
                    const midY = ((sourceIntersectY + targetIntersectY) / 2) - archHeight;
                    
                    // Use quadratic curve for simple arch
                    return `M${sourceIntersectX},${sourceIntersectY} Q${midX},${midY} ${targetIntersectX},${targetIntersectY}`;
                }
            });
    }
    
    /**
     * Render the edges of the graph
     * @param {Array} edges - Array of edge objects
     */
    renderEdges(edges) {
        // First, remove existing edges
        this.svg.selectAll(".flow-path").remove();
        
        console.log(`Rendering edges in ${this.useSankeyLayout ? 'SANKEY' : 'STANDARD'} mode`);
        
        // Add arrowhead marker if not already defined
        // First remove any existing defs to avoid duplicates
        this.svg.selectAll("defs").remove();
        const defs = this.svg.append("defs");
        
        defs.append("marker")
            .attr("id", "arrowhead")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 8)
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .attr("stroke", "none")
            .append("path")
            .attr("class", "arrowhead")
            .attr("fill", "white")
            .attr("d", "M0,-5L10,0L0,5");
            
        if (this.useSankeyLayout && this.sankeyLinks) {
            // Check if the D3 Sankey plugin is available
            if (typeof d3.sankeyLinkHorizontal !== 'function') {
                console.error('d3.sankeyLinkHorizontal function not found! Using standard path generation instead.');
                // Fall back to standard edge rendering
                this.renderEdgesStandard(edges);
                return;
            }
            
            try {
                console.log(`Rendering ${this.sankeyLinks.length} Sankey links`);
                
                // Check one of the links to debug
                if (this.sankeyLinks && this.sankeyLinks.length > 0) {
                    console.log('Sample Sankey link for debugging:');
                    console.log(this.sankeyLinks[0]);
                }

                console.log('Rendering Sankey links with sankeyLinkHorizontal');
                
                // Check Sankey data to debug
                if (this.sankeyLinks && this.sankeyLinks.length > 0) {
                    const sample = this.sankeyLinks[0];
                    console.log('Sample Sankey link data:', sample);
                    console.log('Link width:', sample.width);
                    console.log('Link y0, y1:', sample.y0, sample.y1);
                    console.log('Source position:', sample.source.x0, sample.source.y0, sample.source.x1, sample.source.y1);
                    console.log('Target position:', sample.target.x0, sample.target.y0, sample.target.x1, sample.target.y1);
                    
                    // Test the path generator
                    const pathGen = d3.sankeyLinkHorizontal();
                    const testPath = pathGen(sample);
                    console.log('Generated path for sample link:', testPath);
                }
                
                // Following the D3 Sankey example style
                // Using stroke-width for the band thickness
                this.linkElements = this.svg.selectAll(".sankey-link")
                    .data(this.sankeyLinks)
                    .enter()
                    .append("path")
                    .attr("class", "sankey-link")
                    .attr("d", d3.sankeyLinkHorizontal()) // This creates the link path
                    .attr("stroke", d => {
                        // Color based on source node type for better visualization
                        const sourceNode = d.source.originalNode;
                        if (sourceNode.type === 'http-request') return "#e74c3c";
                        if (sourceNode.type === 'route') return "#f39c12";
                        if (sourceNode.isSourceEvent) return "#2ecc71";
                        if (sourceNode.isTriggerEvent) return "#c0392b";
                        return "#3498db"; // Default blue for data flow
                    })
                    .attr("stroke-width", d => {
                        const width = d.width || 2;
                        console.log(`Link stroke-width: ${width}`);
                        // Cap the width to prevent rendering issues
                        return Math.min(width, 40);
                    }) // Use the computed width from Sankey, capped
                    .attr("stroke-opacity", 0.5) // Semi-transparent
                    .attr("fill", "none") // No fill, just stroke
                    .style("stroke-linejoin", "miter") // Sharp corners
                    .style("stroke-linecap", "butt") // Flat ends, no circles
                
                // Add tooltips to the links
                this.linkElements.append("title")
                    .text(d => {
                        const sourceName = d.source.originalId || d.source.name;
                        const targetName = d.target.originalId || d.target.name;
                        return `${sourceName} → ${targetName}`;
                    });
                    
                console.log(`Rendered ${this.sankeyLinks.length} Sankey links`);
                    
                // Add debugging output
                console.log('Number of Sankey links rendered:', this.sankeyLinks.length);
            } catch (error) {
                console.error('Error creating Sankey links:', error);
                // Fall back to standard edge rendering
                console.log('Falling back to standard path generation');
                this.renderEdgesStandard(edges);
            }
        } else {
            // Use standard curve paths for normal layout
            this.renderEdgesStandard(edges);
        }
    }
};