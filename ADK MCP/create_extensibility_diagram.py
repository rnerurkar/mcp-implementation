#!/usr/bin/env python3
"""
Create MCP Framework Extensibility Architecture Diagram focusing on inheritance patterns
"""
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch, ConnectionPatch, FancyArrowPatch
import numpy as np

def create_extensibility_diagram():
    """Create the MCP Framework Extensibility Architecture Diagram"""
    
    # Create figure and axis
    fig, ax = plt.subplots(1, 1, figsize=(18, 14))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 12)
    ax.axis('off')
    
    # Define colors
    colors = {
        'base_class': '#e3f2fd',
        'concrete_class': '#e8f5e8',
        'security': '#fff3e0',
        'inheritance': '#f3e5f5',
        'border_base': '#1976d2',
        'border_concrete': '#388e3c',
        'border_security': '#f57c00',
        'border_inheritance': '#7b1fa2'
    }
    
    # Title
    ax.text(6, 11.5, 'MCP Framework - Extensibility Architecture', 
            fontsize=22, fontweight='bold', ha='center')
    ax.text(6, 11.1, 'Unlimited Inheritance-Based Scalability with Built-in Security', 
            fontsize=16, ha='center', style='italic')
    
    # ==================== BASE CLASSES LAYER ====================
    ax.text(6, 10.3, 'BASE CLASSES - Template Method Implementation', 
            fontsize=14, fontweight='bold', ha='center', 
            bbox=dict(boxstyle="round,pad=0.3", facecolor=colors['base_class'], alpha=0.8))
    
    # BaseAgent
    base_agent_box = FancyBboxPatch((0.5, 8.5), 3, 1.3,
                                   boxstyle="round,pad=0.1",
                                   facecolor=colors['base_class'],
                                   edgecolor=colors['border_base'],
                                   linewidth=3)
    ax.add_patch(base_agent_box)
    ax.text(2, 9.5, 'BaseAgent', fontsize=14, fontweight='bold', ha='center')
    base_agent_text = """[TEMPLATE] Template Method Pattern
[SHIELD] Security Controls (3)
• Prompt Injection Protection
• Context Size Validation  
• Response Sanitization
[INHERIT] Extensible Base"""
    ax.text(2, 8.9, base_agent_text, fontsize=9, ha='center', va='center')
    
    # BaseMCPServer
    base_mcp_box = FancyBboxPatch((8.5, 8.5), 3, 1.3,
                                 boxstyle="round,pad=0.1",
                                 facecolor=colors['base_class'],
                                 edgecolor=colors['border_base'],
                                 linewidth=3)
    ax.add_patch(base_mcp_box)
    ax.text(10, 9.5, 'BaseMCPServer', fontsize=14, fontweight='bold', ha='center')
    base_mcp_text = """[TEMPLATE] Template Method Pattern
[SHIELD] Security Controls (5)
• Input Sanitization
• Token Validation
• Schema Validation
• Credential Management
• Context Sanitization
[INHERIT] Extensible Base"""
    ax.text(10, 8.9, base_mcp_text, fontsize=9, ha='center', va='center')
    
    # ==================== INHERITANCE ARROWS ====================
    ax.text(6, 7.8, 'INHERITANCE - Automatic Security Propagation', 
            fontsize=14, fontweight='bold', ha='center',
            bbox=dict(boxstyle="round,pad=0.3", facecolor=colors['inheritance'], alpha=0.8))
    
    # ==================== CONCRETE AGENTS LAYER ====================
    ax.text(2, 6.8, 'UNLIMITED AGENTS', fontsize=12, fontweight='bold', ha='center')
    ax.text(2, 6.5, 'Zero Security Code Required', fontsize=10, ha='center', style='italic')
    
    # Agent positions and details
    agent_configs = [
        (0.5, 5, 'UnderwritingAgent', '[RISK] Risk Assessment\n[AUTO] Automated Decisions'),
        (2.5, 5, 'ClaimsAgent', '[PROCESS] Claims Processing\n[WORKFLOW] Automated Review'),
        (0.5, 3.5, 'FraudAgent', '[DETECT] Pattern Analysis\n[ALERT] Real-time Monitoring'),
        (2.5, 3.5, 'ComplianceAgent', '[AUDIT] Compliance Checks\n[REPORT] Regulatory Reports'),
        (1.5, 2, 'CustomAgent N...', '[CUSTOM] Any Business Logic\n[EXTEND] Unlimited Possibilities')
    ]
    
    for x, y, name, details in agent_configs:
        agent_box = FancyBboxPatch((x-0.4, y-0.4), 0.8, 0.8,
                                  boxstyle="round,pad=0.05",
                                  facecolor=colors['concrete_class'],
                                  edgecolor=colors['border_concrete'],
                                  linewidth=2)
        ax.add_patch(agent_box)
        ax.text(x, y+0.15, name, fontsize=9, fontweight='bold', ha='center')
        ax.text(x, y-0.15, details, fontsize=7, ha='center')
        
        # Inheritance arrow from BaseAgent
        arrow = FancyArrowPatch((2, 8.5), (x, y+0.4),
                               arrowstyle='<|-', mutation_scale=15,
                               color=colors['border_inheritance'], alpha=0.7, linewidth=2)
        ax.add_patch(arrow)
    
    # ==================== CONCRETE MCP SERVERS LAYER ====================
    ax.text(10, 6.8, 'UNLIMITED MCP SERVERS', fontsize=12, fontweight='bold', ha='center')
    ax.text(10, 6.5, 'Zero Security Code Required', fontsize=10, ha='center', style='italic')
    
    # MCP Server positions and details
    mcp_configs = [
        (8.5, 5, 'BankingMCPServer', '[BANK] Core Banking APIs\n[SECURE] Transaction Processing'),
        (10.5, 5, 'InsuranceMCPServer', '[POLICY] Policy Management\n[CLAIMS] Claims Processing'),
        (8.5, 3.5, 'RiskMCPServer', '[RISK] Risk Analytics\n[ML] Model Integration'),
        (10.5, 3.5, 'LegacyMCPServer', '[LEGACY] Legacy System Bridge\n[TRANSFORM] Data Translation'),
        (9.5, 2, 'CustomMCPServer N...', '[CUSTOM] Any Business API\n[EXTEND] Unlimited Integration')
    ]
    
    for x, y, name, details in mcp_configs:
        mcp_box = FancyBboxPatch((x-0.4, y-0.4), 0.8, 0.8,
                                boxstyle="round,pad=0.05",
                                facecolor=colors['concrete_class'],
                                edgecolor=colors['border_concrete'],
                                linewidth=2)
        ax.add_patch(mcp_box)
        ax.text(x, y+0.15, name, fontsize=9, fontweight='bold', ha='center')
        ax.text(x, y-0.15, details, fontsize=7, ha='center')
        
        # Inheritance arrow from BaseMCPServer
        arrow = FancyArrowPatch((10, 8.5), (x, y+0.4),
                               arrowstyle='<|-', mutation_scale=15,
                               color=colors['border_inheritance'], alpha=0.7, linewidth=2)
        ax.add_patch(arrow)
    
    # ==================== COMMUNICATION LAYER ====================
    ax.text(6, 1.2, 'SECURE COMMUNICATION', fontsize=12, fontweight='bold', ha='center')
    
    # Communication arrows between agents and MCP servers
    communication_pairs = [
        ((1.5, 4), (9.5, 4)),  # Middle agents to middle servers
        ((1, 3), (9, 3)),      # Lower agents to lower servers
        ((2, 3), (10, 3))      # Other connections
    ]
    
    for (ax1, ay1), (ax2, ay2) in communication_pairs:
        comm_arrow = FancyArrowPatch((ax1, ay1), (ax2, ay2),
                                    arrowstyle='->', mutation_scale=12,
                                    color='#4caf50', alpha=0.8, linewidth=2,
                                    linestyle='--')
        ax.add_patch(comm_arrow)
    
    ax.text(6, 3.5, 'MCP Protocol\nSecure by Design', fontsize=10, ha='center',
            bbox=dict(boxstyle="round,pad=0.2", facecolor='lightgreen', alpha=0.7))
    
    # ==================== SECURITY INHERITANCE HIGHLIGHT ====================
    security_box = FancyBboxPatch((4.5, 8.2), 3, 2,
                                 boxstyle="round,pad=0.1",
                                 facecolor=colors['security'],
                                 edgecolor=colors['border_security'],
                                 linewidth=3, alpha=0.9)
    ax.add_patch(security_box)
    ax.text(6, 9.7, 'SECURITY INHERITANCE', fontsize=12, fontweight='bold', ha='center')
    security_text = """[ZERO-CODE] No Security Implementation
[AUTO-INHERIT] All Security Controls
[CONSISTENT] Enterprise Standards
[VALIDATED] 9 Security Controls
[COMPLIANT] Audit Ready"""
    ax.text(6, 9, security_text, fontsize=10, ha='center', va='center')
    
    # ==================== BUSINESS VALUE CALLOUTS ====================
    # Left side - Development Benefits
    value_box1 = FancyBboxPatch((0.2, 0.2), 3.5, 1,
                               boxstyle="round,pad=0.1",
                               facecolor='#f0f8ff',
                               edgecolor='#4169e1',
                               linewidth=2)
    ax.add_patch(value_box1)
    ax.text(2, 0.9, 'DEVELOPMENT BENEFITS', fontsize=11, fontweight='bold', ha='center')
    ax.text(2, 0.5, '• 6 Hours vs 6 Months per Agent\n• Zero Security Code Required\n• Template Method Consistency\n• Unlimited Scalability', 
            fontsize=9, ha='center')
    
    # Right side - Enterprise Benefits
    value_box2 = FancyBboxPatch((8.3, 0.2), 3.5, 1,
                               boxstyle="round,pad=0.1",
                               facecolor='#f0fff0',
                               edgecolor='#32cd32',
                               linewidth=2)
    ax.add_patch(value_box2)
    ax.text(10, 0.9, 'ENTERPRISE BENEFITS', fontsize=11, fontweight='bold', ha='center')
    ax.text(10, 0.5, '• 40% Development Cost Reduction\n• 100% Security Automation\n• Zero Maintenance Overhead\n• Future-Proof Architecture', 
            fontsize=9, ha='center')
    
    # ==================== LEGEND ====================
    legend_elements = [
        ('Base Classes', colors['base_class'], colors['border_base']),
        ('Concrete Implementations', colors['concrete_class'], colors['border_concrete']),
        ('Security Layer', colors['security'], colors['border_security']),
        ('Inheritance Flow', 'white', colors['border_inheritance'])
    ]
    
    legend_y = 11.8
    for i, (label, facecolor, edgecolor) in enumerate(legend_elements):
        legend_box = FancyBboxPatch((8.5 + i*0.8, legend_y-0.15), 0.3, 0.3,
                                   boxstyle="round,pad=0.02",
                                   facecolor=facecolor,
                                   edgecolor=edgecolor,
                                   linewidth=2)
        ax.add_patch(legend_box)
        ax.text(8.65 + i*0.8, legend_y-0.4, label, fontsize=7, ha='center', rotation=45)
    
    # Save the figure
    plt.tight_layout()
    plt.savefig('MCP_Framework_Extensibility_Architecture.png', dpi=300, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close()
    
    print("✅ Successfully created MCP_Framework_Extensibility_Architecture.png")
    print("📏 Resolution: 300 DPI")
    print("📐 Format: PNG with white background")
    print("🎯 Focus: Inheritance patterns and unlimited extensibility")

if __name__ == "__main__":
    create_extensibility_diagram()
