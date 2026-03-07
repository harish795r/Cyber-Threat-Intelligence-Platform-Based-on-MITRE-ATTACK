// Wait for DOM
document.addEventListener('DOMContentLoaded', function() {
    // 1. Charting Logic
    if (chartDataRaw) {
        const ctx = document.getElementById('attackChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(chartDataRaw),
                datasets: [{
                    data: Object.values(chartDataRaw),
                    backgroundColor: ['#800000', '#26a69a', '#ff3333', '#004d40', '#b0bec5', '#4d0000'],
                    borderColor: '#050505',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom', labels: { color: '#b0bec5', font: { size: 10 } } } }
            }
        });
    }
});

// 2. Export Dashboard
function downloadDashboard() {
    const element = document.getElementById('report-content');
    html2pdf().from(element).set({
        margin: 0.5,
        filename: `${threatName}_Dashboard.pdf`,
        html2canvas: { scale: 2, backgroundColor: '#050505' },
        jsPDF: { orientation: 'landscape' }
    }).save();
}

// 3. Modal Handlers
function openCatalog() { document.getElementById("catalogModal").style.display = "block"; }
function closeCatalog() { document.getElementById("catalogModal").style.display = "none"; }
function selectMalware(name) { document.getElementById("malwareInput").value = name; closeCatalog(); }
function openGlossary() { document.getElementById("glossaryModal").style.display = "block"; }
function closeGlossary() { document.getElementById("glossaryModal").style.display = "none"; }
function closeDetails() { document.getElementById("detailsModal").style.display = "none"; }

function showDetails(name, id, phase, platforms, desc) {
    document.getElementById("modalTitle").innerText = name;
    document.getElementById("modalID").innerText = id;
    document.getElementById("modalPhase").innerText = phase;
    document.getElementById("modalPlatforms").innerText = platforms;
    document.getElementById("modalDesc").innerText = desc;
    document.getElementById("detailsModal").style.display = "block";
}

// Close on outside click
window.onclick = function(event) {
    if (event.target.classList.contains('modal')) {
        closeCatalog(); closeGlossary(); closeDetails();
    }
}