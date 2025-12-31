window.dash_clientside = Object.assign({}, window.dash_clientside, {
    clientside: {
        // Toggle project modal visibility
        toggle_project_modal: function(open_clicks, close_clicks) {
            const modal = document.getElementById('project-manager-modal');
            if (!modal) {
                console.error('Project modal not found');
                return window.dash_clientside.no_update;
            }
            
            // Determine which button was clicked
            const ctx = window.dash_clientside.callback_context;
            if (!ctx || !ctx.triggered || ctx.triggered.length === 0) {
                return {'display': 'none'};
            }
            
            const triggerId = ctx.triggered[0].prop_id.split('.')[0];
            console.log('Project modal triggered by:', triggerId);
            
            if (triggerId === 'btn-project-manager' && open_clicks > 0) {
                console.log('Opening project modal');
                return {
                    'display': 'block',
                    'position': 'fixed',
                    'top': '0',
                    'left': '0',
                    'right': '0',
                    'bottom': '0',
                    'backgroundColor': 'rgba(0,0,0,0.85)',
                    'zIndex': '9999',
                    'paddingTop': '30px'
                };
            } else if (triggerId === 'close-project-modal-btn') {
                console.log('Closing project modal');
                return {'display': 'none'};
            }
            
            return window.dash_clientside.no_update;
        },
        
        setup_chart_observer: function(dark_mode_value) {
            // This function sets up a MutationObserver to fix chart backgrounds in dark mode.
            // It watches for when Plotly charts are added to the DOM and applies
            // transparent backgrounds to prevent the "grey box" flicker.

            const isDarkMode = () => {
                const toggle = document.querySelector('.dark-mode-toggle input[type="checkbox"]');
                return toggle && toggle.checked;
            };

            const applyStyles = (plotEl) => {
                if (isDarkMode()) {
                    // Find the SVG background layer and make it transparent.
                    // This is more targeted than styling all layers.
                    const bgLayer = plotEl.querySelector('.plot-bg, .bg-underplot, .bg');
                    if (bgLayer) {
                        bgLayer.style.fill = 'transparent';
                        bgLayer.style.backgroundColor = 'transparent';
                    }
                }
            };

            // The observer will call applyStyles on any new Plotly charts.
            const observer = new MutationObserver((mutationsList) => {
                for (const mutation of mutationsList) {
                    if (mutation.type === 'childList') {
                        mutation.addedNodes.forEach(node => {
                            if (node.nodeType === 1) {
                                // Check if the added node is a Plotly plot itself
                                if (node.classList.contains('js-plotly-plot')) {
                                    applyStyles(node);
                                } 
                                // Check if the added node contains Plotly plots
                                else {
                                    node.querySelectorAll('.js-plotly-plot').forEach(applyStyles);
                                }
                            }
                        });
                    }
                }
            });

            // Observe the main container where charts are rendered. This is more
            // efficient than observing the entire document body.
            const targetNode = document.getElementById('main-container');
            if (targetNode) {
                observer.observe(targetNode, {
                    childList: true,
                    subtree: true
                });
            }

            // Also apply styles to any charts that might already be on the page.
            document.querySelectorAll('.js-plotly-plot').forEach(applyStyles);

            // This callback only sets up the observer; it doesn't update a Dash component.
            return window.dash_clientside.no_update;
        }
    }
});
// Dark mode dropdown styling - runs on page load
document.addEventListener('DOMContentLoaded', function() {
    // Create a style element for dropdown dark mode
    const style = document.createElement('style');
    style.textContent = `
        /* Dash Dropdown Dark Mode - High Specificity Overrides */
        .Select-control,
        .dash-dropdown .Select-control,
        div[class*="Select"] .Select-control {
            background-color: #2d2d2d !important;
            border-color: #555 !important;
        }
        
        .Select-value-label,
        .Select-placeholder,
        .dash-dropdown .Select-value-label,
        .dash-dropdown .Select-placeholder {
            color: #e0e0e0 !important;
        }
        
        .Select-menu-outer,
        .Select-menu,
        .dash-dropdown .Select-menu-outer,
        .dash-dropdown .Select-menu {
            background-color: #2d2d2d !important;
            border-color: #555 !important;
        }
        
        .Select-option,
        .VirtualizedSelectOption,
        .dash-dropdown .Select-option {
            background-color: #2d2d2d !important;
            color: #e0e0e0 !important;
        }
        
        .Select-option:hover,
        .Select-option.is-focused,
        .VirtualizedSelectFocusedOption {
            background-color: #444 !important;
            color: #ffffff !important;
        }
        
        .Select-option.is-selected {
            background-color: #667eea !important;
            color: #ffffff !important;
        }
        
        .Select-arrow {
            border-color: #e0e0e0 transparent transparent !important;
        }
        
        .Select-input input {
            color: #e0e0e0 !important;
        }
        
        /* Also target modern react-select classes */
        [class*="-menu"],
        [class*="-menuList"],
        [class*="-MenuList"] {
            background-color: #2d2d2d !important;
        }
        
        [class*="-option"] {
            background-color: #2d2d2d !important;
            color: #e0e0e0 !important;
        }
        
        [class*="-option"]:hover {
            background-color: #444 !important;
            color: #fff !important;
        }
        
        [class*="-control"] {
            background-color: #2d2d2d !important;
            border-color: #555 !important;
        }
        
        [class*="-singleValue"],
        [class*="-placeholder"] {
            color: #e0e0e0 !important;
        }
        
        /* Column resize handle styles */
        .column-resize-handle {
            position: absolute;
            right: 0;
            top: 0;
            bottom: 0;
            width: 8px;
            cursor: col-resize;
            background: transparent;
            z-index: 100;
        }
        
        .column-resize-handle:hover,
        .column-resize-handle.resizing {
            background: #667eea;
        }
        
        .dash-spreadsheet th {
            position: relative !important;
        }
    `;
    document.head.appendChild(style);
    
    // Initialize column resizing for DataTable
    initColumnResizing();
    
    // Also observe for dynamically added dropdown menus
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            mutation.addedNodes.forEach(function(node) {
                if (node.nodeType === 1) {
                    // Get className as string (handles SVG elements which have SVGAnimatedString)
                    const classNameStr = typeof node.className === 'string' 
                        ? node.className 
                        : (node.className && node.className.baseVal) || '';
                    
                    // Check for dropdown menu elements
                    if (node.classList && (
                        node.classList.contains('Select-menu-outer') ||
                        node.classList.contains('Select-menu') ||
                        classNameStr.includes('-menu')
                    )) {
                        node.style.backgroundColor = '#2d2d2d';
                        node.style.borderColor = '#555';
                    }
                    // Style any option elements
                    const options = node.querySelectorAll('.Select-option, [class*="-option"]');
                    options.forEach(function(opt) {
                        opt.style.backgroundColor = '#2d2d2d';
                        opt.style.color = '#e0e0e0';
                    });
                    
                    // Re-initialize column resizing when table updates
                    if (node.classList && node.classList.contains('dash-spreadsheet')) {
                        setTimeout(initColumnResizing, 100);
                    }
                }
            });
        });
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
});

// Column resizing functionality
function initColumnResizing() {
    const tables = document.querySelectorAll('.dash-spreadsheet');
    
    tables.forEach(function(table) {
        const headerCells = table.querySelectorAll('th');
        
        headerCells.forEach(function(th, index) {
            // Skip if already has resize handle
            if (th.querySelector('.column-resize-handle')) return;
            
            // Create resize handle
            const handle = document.createElement('div');
            handle.className = 'column-resize-handle';
            handle.setAttribute('data-col-index', index);
            th.style.position = 'relative';
            th.appendChild(handle);
            
            let startX, startWidth, columnIndex;
            
            handle.addEventListener('mousedown', function(e) {
                e.preventDefault();
                e.stopPropagation();
                
                startX = e.pageX;
                columnIndex = parseInt(this.getAttribute('data-col-index'));
                startWidth = th.offsetWidth;
                
                handle.classList.add('resizing');
                
                document.addEventListener('mousemove', onMouseMove);
                document.addEventListener('mouseup', onMouseUp);
            });
            
            function onMouseMove(e) {
                const diff = e.pageX - startX;
                const newWidth = Math.max(50, startWidth + diff);
                
                // Update the header cell width
                th.style.width = newWidth + 'px';
                th.style.minWidth = newWidth + 'px';
                th.style.maxWidth = newWidth + 'px';
                
                // Update all cells in this column
                const allRows = table.querySelectorAll('tr');
                allRows.forEach(function(row) {
                    const cells = row.querySelectorAll('td, th');
                    if (cells[columnIndex]) {
                        cells[columnIndex].style.width = newWidth + 'px';
                        cells[columnIndex].style.minWidth = newWidth + 'px';
                        cells[columnIndex].style.maxWidth = newWidth + 'px';
                    }
                });
            }
            
            function onMouseUp() {
                handle.classList.remove('resizing');
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
            }
        });
    });
}

// Re-run on interval to catch dynamically loaded tables
setInterval(function() {
    const tables = document.querySelectorAll('.dash-spreadsheet th:not(:has(.column-resize-handle))');
    if (tables.length > 0) {
        initColumnResizing();
    }
}, 10000);

// Direct DOM-based project modal toggle (more reliable than Dash callbacks)
document.addEventListener('DOMContentLoaded', function() {
    // Wait for Dash to render, then attach click handlers
    setTimeout(function() {
        setupProjectModalHandlers();
    }, 2000);
});

function setupProjectModalHandlers() {
    const openBtn = document.getElementById('btn-project-manager');
    const closeBtn = document.getElementById('close-project-modal-btn');
    const modal = document.getElementById('project-manager-modal');
    
    if (openBtn && modal) {
        openBtn.addEventListener('click', function(e) {
            console.log('Project button clicked - opening modal');
            modal.style.display = 'block';
            modal.style.position = 'fixed';
            modal.style.top = '0';
            modal.style.left = '0';
            modal.style.right = '0';
            modal.style.bottom = '0';
            modal.style.backgroundColor = 'rgba(0,0,0,0.85)';
            modal.style.zIndex = '9999';
            modal.style.paddingTop = '30px';
        });
        console.log('Project modal open handler attached');
    } else {
        console.log('Project button or modal not found, retrying in 2s');
        setTimeout(setupProjectModalHandlers, 2000);
    }
    
    if (closeBtn && modal) {
        closeBtn.addEventListener('click', function(e) {
            console.log('Close button clicked - hiding modal');
            modal.style.display = 'none';
        });
        console.log('Project modal close handler attached');
    }
}

// Also run when page might have been updated by Dash
setInterval(function() {
    const openBtn = document.getElementById('btn-project-manager');
    if (openBtn && !openBtn.hasAttribute('data-modal-handler')) {
        openBtn.setAttribute('data-modal-handler', 'true');
        setupProjectModalHandlers();
    }
}, 3000);