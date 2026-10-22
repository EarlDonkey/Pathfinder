from __future__ import annotations

import logging
import sys
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QHBoxLayout, 
    QHeaderView, QLabel, QLineEdit, QMainWindow, QMessageBox, 
    QProgressBar, QPushButton, QStackedWidget, QTableWidget, 
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget
)

from vuln_toolkit.core.engine import ScannerOrchestrator
from vuln_toolkit.core.plugin_base import TargetType, Severity
from vuln_toolkit.core.reporter import render_html
from vuln_toolkit.core.store import save_scan

# =============================================================================
# GLOBAL STYLESHEET (Mimics the dark-mode dashboard)
# =============================================================================
STYLESHEET = """
QMainWindow {
    background-color: #0b0f19;
}
QWidget {
    color: #e2e8f0;
    font-family: 'Segoe UI', sans-serif;
}
/* Sidebar */
#sidebar {
    background-color: #0f172a;
    border-right: 1px solid #1e293b;
}
#sidebar QPushButton {
    background-color: transparent;
    color: #94a3b8;
    text-align: left;
    padding: 12px 20px;
    border: none;
    font-size: 14px;
    font-weight: 600;
    border-radius: 6px;
    margin: 2px 10px;
}
#sidebar QPushButton:hover {
    background-color: #1e293b;
    color: #e2e8f0;
}
#sidebar QPushButton:checked {
    background-color: #1e293b;
    color: #38bdf8;
    border-left: 3px solid #38bdf8;
}
#logo {
    font-size: 20px;
    font-weight: 800;
    color: #e2e8f0;
    padding: 20px;
}
/* Panels & Cards */
QFrame.panel {
    background-color: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 10px;
}
/* Change this block in the STYLESHEET variable: */
QFrame.metric-card {
    border-radius: 10px;
    /* Removed padding: 15px; to prevent double-padding clipping */
}
#cardTotal { background-color: #4c1d95; border: 1px solid #6d28d9; }
#cardCritical { background-color: #7f1d1d; border: 1px solid #b91c1c; }
#cardHigh { background-color: #78350f; border: 1px solid #b45309; }
#cardMedium { background-color: #14532d; border: 1px solid #15803d; }

.metric-title { font-size: 13px; font-weight: 600; color: rgba(255,255,255,0.8); }
.metric-value { font-size: 34px; font-weight: 800; color: #ffffff; }

/* Inputs & Buttons */
QLineEdit, QComboBox {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 8px 12px;
    color: #e2e8f0;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #38bdf8;
}
QPushButton.primary {
    background-color: #6d28d9;
    color: white;
    font-weight: 700;
    border-radius: 6px;
    padding: 8px 20px;
    border: none;
}
QPushButton.primary:hover { background-color: #7c3aed; }
QPushButton.primary:disabled { background-color: #334155; color: #64748b; }
QPushButton.secondary {
    background-color: #1e293b;
    color: #38bdf8;
    border: 1px solid #38bdf8;
    border-radius: 6px;
    padding: 8px 20px;
    font-weight: 600;
}
QPushButton.secondary:hover { background-color: #0f172a; }
QPushButton.secondary:disabled { border: 1px solid #334155; color: #64748b; }

/* Table */
QTableWidget {
    background-color: transparent;
    border: none;
    gridline-color: transparent;
    selection-background-color: #1e293b;
}
QHeaderView::section {
    background-color: #0f172a;
    color: #94a3b8;
    font-weight: 700;
    border: none;
    border-bottom: 1px solid #334155;
    padding: 8px;
    text-align: left;
}
QTableWidget::item {
    border-bottom: 1px solid #1e293b;
    padding: 6px;
}
/* Scrollbars */
QScrollBar:vertical {
    border: none;
    background: #0b0f19;
    width: 10px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #334155;
    min-height: 20px;
    border-radius: 5px;
}
QScrollBar::handle:vertical:hover { background: #475569; }
"""

# =============================================================================
# Background Worker
# =============================================================================
class ScanWorker(QObject):
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, target: str, mode: str):
        super().__init__()
        self.target = target
        self.mode = mode

    def run(self):
        try:
            orch = ScannerOrchestrator(enrich=True, use_suppressions=True)
            if self.mode == "online":
                result = orch.run(TargetType.ONLINE, self.target)
            else:
                result = orch.run(TargetType.OFFLINE, self.target)
                
            try:
                save_scan(result)
            except Exception as e:
                logging.error("Failed to save to DB: %s", e)

            self.finished.emit(result)
        except Exception as e:
            logging.exception("Scan failed")
            self.error.emit(str(e))

# =============================================================================
# Logging Bridge
# =============================================================================
class QtLogHandler(QObject, logging.Handler):
    log_signal = Signal(str)

    def __init__(self):
        QObject.__init__(self)
        logging.Handler.__init__(self)

    def emit(self, record):
        self.log_signal.emit(self.format(record))

# =============================================================================
# Custom Metric Card Widget
# =============================================================================
class MetricCard(QFrame):
    def __init__(self, title: str, obj_name: str):
        super().__init__()
        self.setProperty("class", "metric-card")
        self.setObjectName(obj_name)
        self.setFixedHeight(100)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        self.title_label = QLabel(title)
        self.title_label.setProperty("class", "metric-title")
        
        self.value_label = QLabel("0")
        self.value_label.setProperty("class", "metric-value")
        
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        
    def set_value(self, val: int):
        self.value_label.setText(str(val))

# =============================================================================
# Main Application Window
# =============================================================================
class VulnToolkitGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Vuln-Toolkit Dashboard")
        self.resize(1100, 750)
        self.last_result = None

        # Apply Stylesheet
        self.setStyleSheet(STYLESHEET)

        # Main Layout (Horizontal: Sidebar + Content)
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 1. Sidebar
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(200)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        
        logo = QLabel("⚡ VulnToolkit")
        logo.setObjectName("logo")
        sidebar_layout.addWidget(logo)

        self.btn_nav_dash = QPushButton("Dashboard")
        self.btn_nav_dash.setCheckable(True)
        self.btn_nav_dash.setChecked(True)
        self.btn_nav_dash.clicked.connect(lambda: self.switch_page(0))
        
        self.btn_nav_logs = QPushButton("Live Logs")
        self.btn_nav_logs.setCheckable(True)
        self.btn_nav_logs.clicked.connect(lambda: self.switch_page(1))

        sidebar_layout.addWidget(self.btn_nav_dash)
        sidebar_layout.addWidget(self.btn_nav_logs)
        sidebar_layout.addStretch()
        
        main_layout.addWidget(sidebar)

        # 2. Content Area (Stacked Widget)
        self.pages = QStackedWidget()
        main_layout.addWidget(self.pages)

        # --- Page 0: Dashboard ---
        self.page_dash = QWidget()
        dash_layout = QVBoxLayout(self.page_dash)
        dash_layout.setContentsMargins(30, 30, 30, 30)
        dash_layout.setSpacing(20)

        # Header row
        header_layout = QHBoxLayout()
        title = QLabel("Network Overview")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #ffffff;")
        self.report_btn = QPushButton("Save HTML Report")
        self.report_btn.setProperty("class", "secondary")
        self.report_btn.setEnabled(False)
        self.report_btn.clicked.connect(self.save_report)
        
        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(self.report_btn)
        dash_layout.addLayout(header_layout)

        # Scan Controls Panel
        controls_panel = QFrame()
        controls_panel.setProperty("class", "panel")
        controls_layout = QHBoxLayout(controls_panel)
        controls_layout.setContentsMargins(20, 20, 20, 20)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target (e.g., example.com or C:\\path)")
        self.target_input.setMinimumHeight(38)
        
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["online", "offline"])
        self.mode_combo.setMinimumHeight(38)
        
        self.scan_btn = QPushButton("Run Scan Now")
        self.scan_btn.setProperty("class", "primary")
        self.scan_btn.setMinimumHeight(38)
        self.scan_btn.clicked.connect(self.start_scan)

        controls_layout.addWidget(QLabel("Target:"))
        controls_layout.addWidget(self.target_input, stretch=1)
        controls_layout.addWidget(QLabel("Mode:"))
        controls_layout.addWidget(self.mode_combo)
        controls_layout.addWidget(self.scan_btn)
        
        dash_layout.addWidget(controls_panel)

        # Metrics Row
        metrics_layout = QHBoxLayout()
        metrics_layout.setSpacing(15)
        
        self.card_total = MetricCard("Total Findings", "cardTotal")
        self.card_crit = MetricCard("Critical", "cardCritical")
        self.card_high = MetricCard("High", "cardHigh")
        self.card_med = MetricCard("Medium / Low", "cardMedium")
        
        metrics_layout.addWidget(self.card_total)
        metrics_layout.addWidget(self.card_crit)
        metrics_layout.addWidget(self.card_high)
        metrics_layout.addWidget(self.card_med)
        
        dash_layout.addLayout(metrics_layout)

        # Findings Table Panel
        table_panel = QFrame()
        table_panel.setProperty("class", "panel")
        table_layout = QVBoxLayout(table_panel)
        table_layout.setContentsMargins(20, 20, 20, 20)
        
        table_title = QLabel("Recent Findings")
        table_title.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px;")
        table_layout.addWidget(table_title)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Severity", "Title", "Target", "Plugin"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        table_layout.addWidget(self.table)
        
        dash_layout.addWidget(table_panel, stretch=1)
        
        self.pages.addWidget(self.page_dash)

        # --- Page 1: Live Logs ---
        self.page_logs = QWidget()
        logs_layout = QVBoxLayout(self.page_logs)
        logs_layout.setContentsMargins(30, 30, 30, 30)
        
        log_title = QLabel("Live Execution Log")
        log_title.setStyleSheet("font-size: 20px; font-weight: bold;")
        logs_layout.addWidget(log_title)
        
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 10))
        self.log_view.setStyleSheet("background-color: #0f172a; border: 1px solid #1e293b; padding: 10px; color: #38bdf8;")
        logs_layout.addWidget(self.log_view)
        
        self.pages.addWidget(self.page_logs)

        # Status Bar & Progress
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedHeight(4)
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet("QProgressBar { border: none; background: #0f172a; } QProgressBar::chunk { background: #38bdf8; }")
        self.progress.hide()
        dash_layout.addWidget(self.progress)

        # Logging Interceptor
        self.log_handler = QtLogHandler()
        self.log_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%H:%M:%S"))
        self.log_handler.log_signal.connect(self.append_log)
        logging.getLogger().addHandler(self.log_handler)
        logging.getLogger().setLevel(logging.INFO)

        self.worker_thread = None

    def switch_page(self, index):
        self.pages.setCurrentIndex(index)
        self.btn_nav_dash.setChecked(index == 0)
        self.btn_nav_logs.setChecked(index == 1)

    def append_log(self, text: str):
        self.log_view.append(text)
        scrollbar = self.log_view.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def start_scan(self):
        target = self.target_input.text().strip()
        mode = self.mode_combo.currentText()

        if not target:
            QMessageBox.warning(self, "Error", "Please enter a target.")
            return

        self.log_view.clear()
        self.scan_btn.setEnabled(False)
        self.report_btn.setEnabled(False)
        self.progress.show()
        self.table.setRowCount(0)
        
        self.card_total.set_value(0)
        self.card_crit.set_value(0)
        self.card_high.set_value(0)
        self.card_med.set_value(0)
        
        self.switch_page(1)  # Switch to logs while scanning

        self.worker_thread = QThread()
        self.worker = ScanWorker(target, mode)
        self.worker.moveToThread(self.worker_thread)
        
        self.worker_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.scan_finished)
        self.worker.error.connect(self.scan_error)
        
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.worker_thread.deleteLater)
        
        self.worker_thread.start()

    def scan_finished(self, result):
        self.last_result = result
        self.progress.hide()
        self.scan_btn.setEnabled(True)
        self.report_btn.setEnabled(True)
        self.switch_page(0) # Switch back to dashboard

        # Populate Metrics
        crit = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in result.findings if f.severity == Severity.HIGH)
        med_low = sum(1 for f in result.findings if f.severity in (Severity.MEDIUM, Severity.LOW))
        
        self.card_total.set_value(len(result.findings))
        self.card_crit.set_value(crit)
        self.card_high.set_value(high)
        self.card_med.set_value(med_low)

        # Populate Table
        findings = result.sorted_findings()
        self.table.setRowCount(len(findings))
        
        for row, f in enumerate(findings):
            sev_item = QTableWidgetItem(f.severity.value.upper())
            sev_item.setForeground(QColor("#ef4444" if f.severity == Severity.CRITICAL else "#f59e0b" if f.severity == Severity.HIGH else "#38bdf8"))
            sev_item.setFont(QFont("Segoe UI", 9, QFont.Bold))
            
            self.table.setItem(row, 0, sev_item)
            self.table.setItem(row, 1, QTableWidgetItem(f.title))
            self.table.setItem(row, 2, QTableWidgetItem(f.target))
            self.table.setItem(row, 3, QTableWidgetItem(f.plugin))
            
            self.table.setRowHeight(row, 30)

    def scan_error(self, err_msg):
        self.progress.hide()
        self.scan_btn.setEnabled(True)
        self.switch_page(0)
        QMessageBox.critical(self, "Scan Error", f"An error occurred:\n{err_msg}")

    def save_report(self):
        if not self.last_result:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save HTML Report", "vulnerability-report.html", "HTML Files (*.html)"
        )
        
        if file_path:
            try:
                html_content = render_html(self.last_result)
                Path(file_path).write_text(html_content, encoding="utf-8")
                QMessageBox.information(self, "Success", f"Report saved to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save report:\n{e}")

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = VulnToolkitGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()