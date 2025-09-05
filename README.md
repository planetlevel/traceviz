# TraceViz - Vulnerability Trace Viewer

WARNING: This is a vibe coded experimental prototype!

A browser-based visualization tool for analyzing vulnerability traces and data flow in applications. TraceViz renders vulnerability traces as interactive directed acyclic graphs (DAG) with support for both standard and Sankey diagram layouts.

## Features

- **Dual Visualization Modes**: 
  - Standard DAG view with circular nodes and curved edges
  - Sankey diagram view with thick flowing bands showing data propagation
- **Interactive Graph Visualization**: Explore vulnerability traces through zoomable, pannable graphs
- **Auto-fit Zoom**: Automatically fits the entire graph in the viewport
- **Node Grouping**: Automatically groups related events for cleaner visualization
- **Color-coded Event Types**: Visual distinction between HTTP requests, routes, sources, data flows, and violations
- **Detailed Information**: Hover tooltips and click-to-view details for each node
- **Taint Highlighting**: Visual highlighting of tainted data in red
- **Support for XML trace files**: Both directly and within ZIP archives
- **Responsive design**: Works on various screen sizes

## Getting Started

### Prerequisites

- A modern web browser (Chrome, Firefox, Safari, Edge)

### Installation

1. Clone this repository:
```
git clone https://github.com/yourusername/traceviz.git
```

2. Open your web browser and navigate to:
```
file:///[path-to]traceviz/index.html
```

### Usage

1. **Upload a Trace File**: Click "Choose File" to select an XML or ZIP file containing vulnerability traces
2. **Load Sample Data**: Click "Load Sample Data" to load the included example trace
3. **Toggle Visualization Mode**: 
   - Click "Toggle Sankey View" to switch between standard DAG and Sankey diagram layouts
   - Sankey view shows data flows as thick bands with width proportional to flow volume
4. **Interact with the Graph**:
   - **Zoom**: Scroll or use zoom controls
   - **Pan**: Click and drag on the background
   - **Node Details**: Click on nodes to see detailed information in the sidebar
   - **Tooltips**: Hover over nodes to see quick information
5. **Understand the Visualization**:
   - **Red (H)**: HTTP Request entry points
   - **Orange (R)**: Application routes
   - **Green (S)**: Data sources/creation points
   - **Blue (D)**: Data flow/propagation events
   - **Dark Red (V)**: Security violations detected
   - Tainted parameters are highlighted in red within node details

## Project Structure

```
traceviz/
├── index.html              # Main HTML file
├── server.js              # Node.js development server
├── css/
│   └── styles.css         # Application styles
├── js/
│   ├── app.js            # Main application controller
│   ├── graph-renderer.js # Graph rendering engine (DAG & Sankey)
│   └── trace-parser.js   # XML trace file parser
├── libs/
│   ├── d3.v7.min.js      # D3.js visualization library
│   ├── d3-sankey/        # D3 Sankey diagram plugin
│   └── jszip.min.js      # ZIP file handling
└── test-traces/          # Sample trace files
```

## Technologies Used

- **D3.js v7**: Core visualization library for interactive graphs
- **D3 Sankey**: Plugin for Sankey diagram layouts
- **JSZip**: For handling ZIP archives containing trace files
- **Vanilla JavaScript**: No framework dependencies
- **CSS3**: Modern styling with dark theme

## License

MIT License - See LICENSE file for details

## Acknowledgments

- [Contrast Security](https://www.contrastsecurity.com/) for the Assess product and trace format
- [D3.js](https://d3js.org/) for powerful visualization capabilities
- [d3-sankey](https://github.com/d3/d3-sankey) for Sankey diagram support
- [JSZip](https://stuk.github.io/jszip/) for ZIP file handling
