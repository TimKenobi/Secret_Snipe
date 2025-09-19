window.dash_clientside = Object.assign({}, window.dash_clientside, {
    clientside: {
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
