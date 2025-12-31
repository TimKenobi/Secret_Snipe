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

// Project modal - bypass Dash completely with pure JavaScript modal
setTimeout(function() {
    const projectBtn = document.getElementById('btn-project-manager');
    if (projectBtn && !projectBtn.hasAttribute('data-js-modal')) {
        projectBtn.setAttribute('data-js-modal', 'true');
        
        projectBtn.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            // Remove any existing JS modal
            const existing = document.getElementById('js-project-modal');
            if (existing) existing.remove();
            
            // Create modal overlay
            const overlay = document.createElement('div');
            overlay.id = 'js-project-modal';
            overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.9);z-index:99999;display:flex;align-items:flex-start;justify-content:center;padding-top:30px;overflow-y:auto;';
            
            // Create modal content
            const content = document.createElement('div');
            content.style.cssText = 'background:#2d3748;padding:25px;border-radius:8px;max-width:700px;width:90%;max-height:85vh;overflow-y:auto;color:#e0e0e0;border:1px solid #555;';
            content.innerHTML = `
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
                    <h2 style="margin:0;color:#60a5fa;">📂 Project & Directory Management</h2>
                    <button id="js-modal-close" style="background:none;border:none;color:#aaa;font-size:24px;cursor:pointer;">✕</button>
                </div>
                <p style="color:#9ca3af;margin-bottom:20px;">Manage scan directories and trigger scans.</p>
                
                <div style="background:#1f2937;padding:15px;border-radius:8px;margin-bottom:20px;">
                    <h4 style="color:#e0e0e0;margin:0 0 10px 0;">📁 Scan Directories</h4>
                    <div id="js-dir-list" style="color:#9ca3af;">Loading...</div>
                </div>
                
                <div style="background:#1f2937;padding:15px;border-radius:8px;margin-bottom:20px;">
                    <h4 style="color:#e0e0e0;margin:0 0 10px 0;">🔍 Trigger Manual Scan</h4>
                    <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
                        <select id="js-scan-dir" style="padding:8px;background:#3d3d3d;color:#e0e0e0;border:1px solid #555;border-radius:4px;">
                            <option value="">Loading directories...</option>
                        </select>
                        <select id="js-scan-type" style="padding:8px;background:#3d3d3d;color:#e0e0e0;border:1px solid #555;border-radius:4px;">
                            <option value="full">🔄 Full Scan</option>
                            <option value="custom_only">🔍 Custom Only</option>
                            <option value="gitleaks_only">🔐 Gitleaks Only</option>
                            <option value="trufflehog_only">🐷 TruffleHog Only</option>
                        </select>
                        <button id="js-start-scan" style="padding:8px 16px;background:#3b82f6;color:white;border:none;border-radius:6px;cursor:pointer;font-weight:bold;">▶️ Start Scan</button>
                    </div>
                    <div id="js-scan-result" style="margin-top:10px;"></div>
                </div>
                
                <div style="background:#1f2937;padding:15px;border-radius:8px;">
                    <h4 style="color:#e0e0e0;margin:0 0 10px 0;">⏳ Pending/Running Scans</h4>
                    <div id="js-pending-list" style="color:#9ca3af;">Loading...</div>
                </div>
            `;
            
            overlay.appendChild(content);
            document.body.appendChild(overlay);
            
            // Close button
            document.getElementById('js-modal-close').addEventListener('click', function() {
                overlay.remove();
            });
            
            // Close on overlay click
            overlay.addEventListener('click', function(e) {
                if (e.target === overlay) overlay.remove();
            });
            
            // Escape key to close
            document.addEventListener('keydown', function escHandler(e) {
                if (e.key === 'Escape') {
                    overlay.remove();
                    document.removeEventListener('keydown', escHandler);
                }
            });
            
            // Fetch project data from API
            fetch('/api/projects/directories')
                .then(r => r.json())
                .then(data => {
                    if (data.directories && data.directories.length > 0) {
                        let html = '';
                        let options = '<option value="">Select directory...</option>';
                        data.directories.forEach(d => {
                            const status = d.is_active ? '✅' : '⏸️';
                            const lastScan = d.last_scan_at || 'Never';
                            html += '<div style="padding:8px;border-bottom:1px solid #444;"><strong style="color:#e0e0e0;">' + status + ' ' + d.display_name + '</strong> <span style="color:#6b7280;font-size:12px;">(' + d.scan_schedule + ')</span><br><span style="color:#9ca3af;font-size:12px;">' + d.directory_path + '</span><span style="color:#6b7280;font-size:11px;"> | Last: ' + lastScan + ' | Files: ' + (d.total_files || 0).toLocaleString() + ' | Findings: ' + (d.total_findings || 0).toLocaleString() + '</span></div>';
                            if (d.is_active) {
                                options += '<option value="' + d.id + '">' + d.display_name + '</option>';
                            }
                        });
                        document.getElementById('js-dir-list').innerHTML = html;
                        document.getElementById('js-scan-dir').innerHTML = options;
                    } else {
                        document.getElementById('js-dir-list').innerHTML = '<p style="font-style:italic;">No directories configured.</p>';
                    }
                })
                .catch(err => {
                    document.getElementById('js-dir-list').innerHTML = '<p style="color:#ef4444;">Error loading: ' + err + '</p>';
                });
            
            // Fetch pending scans
            fetch('/api/projects/pending-scans')
                .then(r => r.json())
                .then(data => {
                    if (data.pending && data.pending.length > 0) {
                        let html = '';
                        data.pending.forEach(p => {
                            const color = p.status === 'running' ? '#22c55e' : (p.status === 'pending' ? '#f59e0b' : '#3b82f6');
                            html += '<div style="padding:5px;border-bottom:1px solid #333;"><span style="color:' + color + ';font-weight:bold;">⏳ ' + p.scan_type + '</span> <span style="color:#9ca3af;"> - ' + p.status + '</span></div>';
                        });
                        document.getElementById('js-pending-list').innerHTML = html;
                    } else {
                        document.getElementById('js-pending-list').innerHTML = '<p style="font-style:italic;">No pending scans.</p>';
                    }
                })
                .catch(err => {
                    document.getElementById('js-pending-list').innerHTML = '<p style="color:#ef4444;">Error: ' + err + '</p>';
                });
            
            // Start scan button
            document.getElementById('js-start-scan').addEventListener('click', function() {
                const dirId = document.getElementById('js-scan-dir').value;
                const scanType = document.getElementById('js-scan-type').value;
                if (!dirId) {
                    document.getElementById('js-scan-result').innerHTML = '<span style="color:#f59e0b;">Please select a directory</span>';
                    return;
                }
                document.getElementById('js-scan-result').innerHTML = '<span style="color:#3b82f6;">Starting scan...</span>';
                fetch('/api/projects/trigger-scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({directory_id: parseInt(dirId), scan_type: scanType})
                })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('js-scan-result').innerHTML = '<span style="color:#22c55e;">✅ Scan queued! ID: ' + (data.request_id || 'unknown').substring(0,8) + '...</span>';
                    } else {
                        document.getElementById('js-scan-result').innerHTML = '<span style="color:#ef4444;">❌ ' + (data.error || 'Failed') + '</span>';
                    }
                })
                .catch(err => {
                    document.getElementById('js-scan-result').innerHTML = '<span style="color:#ef4444;">❌ Error: ' + err + '</span>';
                });
            });
            
            console.log('✅ JavaScript modal opened');
        }, true);
        
        console.log('✅ JavaScript modal handler attached to Projects button');
    }
}, 2000);

