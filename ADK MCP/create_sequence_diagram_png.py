#!/usr/bin/env python3
"""
Generate PNG diagram for VSCode Copilot Agent MCP Server End-to-End Sequence Diagram
with corrected security controls analysis based on SECURITY_CONTROLS_OVERVIEW.md
"""

import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch, ConnectionPatch
import numpy as np

def create_sequence_diagram():
    # Create figure with high DPI for better quality
    fig, ax = plt.subplots(1, 1, figsize=(16, 20), dpi=300)
    
    # Define colors
    colors = {
        'user': '#E3F2FD',
        'agent': '#FFEBEE', 
        'mcp_server': '#E8F5E8',
        'rally': '#FFF3E0',
        'security': '#C8E6C9',
        'optional': '#FFF9C4',
        'skipped': '#FFCDD2',
        'arrow': '#1976D2',
        'security_arrow': '#2E7D32',
        'text': '#212121'
    }
    
    # Define component positions
    components = {
        'user': {'x': 1, 'label': '👤 User\n(VSCode IDE)'},
        'agent': {'x': 4, 'label': '🤖 GitHub Copilot\nAgent'},
        'mcp_server': {'x': 7, 'label': '🛡️ MCP Server\n(6 Mandatory + 2 Optional\nSecurity Controls)'},
        'rally': {'x': 10, 'label': '🏢 Rally API\n(Business System)'}
    }
    
    # Draw component headers
    header_y = 19
    for comp, info in components.items():
        # Component box
        box = FancyBboxPatch(
            (info['x']-0.8, header_y-0.5), 1.6, 1,
            boxstyle="round,pad=0.1",
            facecolor=colors[comp if comp != 'mcp_server' else 'security'],
            edgecolor='black',
            linewidth=2
        )
        ax.add_patch(box)
        
        # Component label
        ax.text(info['x'], header_y, info['label'], 
                ha='center', va='center', fontsize=10, fontweight='bold',
                color=colors['text'])
        
        # Vertical lifeline
        ax.plot([info['x'], info['x']], [header_y-0.5, 1], 
                'k--', alpha=0.3, linewidth=1)
    
    # Define sequence steps with security controls
    sequence_steps = [
        {
            'y': 17.5,
            'from': 'user',
            'to': 'agent', 
            'label': '1. "Create Rally story for feature X"',
            'type': 'request'
        },
        {
            'y': 16.5,
            'from': 'agent',
            'to': 'mcp_server',
            'label': '2. OAuth 2.1 Request + User Query',
            'type': 'request',
            'security': ['InputSanitizer', 'GoogleCloudTokenValidator', 'SchemaValidator']
        },
        {
            'y': 15.5,
            'from': 'mcp_server',
            'to': 'mcp_server',
            'label': '3. Security Gateway Processing',
            'type': 'internal',
            'security': ['CredentialManager', 'ToolExposureController']
        },
        {
            'y': 14.5,
            'from': 'mcp_server',
            'to': 'rally',
            'label': '4. Secure API Call (with injected credentials)',
            'type': 'request'
        },
        {
            'y': 13.5,
            'from': 'rally',
            'to': 'mcp_server',
            'label': '5. Rally API Response',
            'type': 'response'
        },
        {
            'y': 12.5,
            'from': 'mcp_server',
            'to': 'mcp_server',
            'label': '6. Response Security Processing',
            'type': 'internal',
            'security': ['ContextSanitizer']
        },
        {
            'y': 11.5,
            'from': 'mcp_server',
            'to': 'agent',
            'label': '7. Sanitized Response (PII removed)',
            'type': 'response'
        },
        {
            'y': 10.5,
            'from': 'agent',
            'to': 'user',
            'label': '8. Processed Result',
            'type': 'response'
        }
    ]
    
    # Draw sequence arrows and labels
    for step in sequence_steps:
        if step['type'] == 'internal':
            # Self-loop for internal processing
            x_pos = components[step['from']]['x']
            
            # Draw self-loop
            loop_width = 0.8
            loop = patches.FancyArrowPatch(
                (x_pos + 0.1, step['y']), (x_pos + loop_width, step['y']),
                arrowstyle='->', mutation_scale=15,
                color=colors['security_arrow'], linewidth=2
            )
            ax.add_patch(loop)
            
            # Return arrow
            return_arrow = patches.FancyArrowPatch(
                (x_pos + loop_width, step['y'] - 0.1), (x_pos + 0.1, step['y'] - 0.1),
                arrowstyle='->', mutation_scale=15,
                color=colors['security_arrow'], linewidth=2
            )
            ax.add_patch(return_arrow)
            
            # Label
            ax.text(x_pos + loop_width/2, step['y'] + 0.3, step['label'],
                    ha='center', va='bottom', fontsize=9, fontweight='bold',
                    bbox=dict(boxstyle="round,pad=0.3", facecolor=colors['security'], alpha=0.8))
        else:
            # Regular arrow between components
            from_x = components[step['from']]['x']
            to_x = components[step['to']]['x']
            
            arrow_color = colors['security_arrow'] if 'security' in step else colors['arrow']
            
            arrow = patches.FancyArrowPatch(
                (from_x, step['y']), (to_x, step['y']),
                arrowstyle='->', mutation_scale=15,
                color=arrow_color, linewidth=2
            )
            ax.add_patch(arrow)
            
            # Label
            label_x = (from_x + to_x) / 2
            bg_color = colors['security'] if 'security' in step else 'white'
            ax.text(label_x, step['y'] + 0.2, step['label'],
                    ha='center', va='bottom', fontsize=9,
                    bbox=dict(boxstyle="round,pad=0.3", facecolor=bg_color, alpha=0.8))
        
        # Add security controls annotation
        if 'security' in step:
            security_text = "Security: " + ", ".join(step['security'])
            ax.text(components['mcp_server']['x'], step['y'] - 0.3, security_text,
                    ha='center', va='top', fontsize=8, style='italic',
                    color=colors['security_arrow'],
                    bbox=dict(boxstyle="round,pad=0.2", facecolor=colors['security'], alpha=0.6))
    
    # Add security controls legend
    legend_y_start = 9
    ax.text(1, legend_y_start, "🔒 MCP Framework Security Controls Analysis", 
            fontsize=14, fontweight='bold', color=colors['text'])
    
    # Mandatory controls
    mandatory_controls = [
        "1. InputSanitizer - Prompt injection protection",
        "2. GoogleCloudTokenValidator - OAuth 2.1 validation", 
        "3. SchemaValidator - JSON-RPC 2.0 compliance",
        "4. CredentialManager - Google Cloud Secret Manager",
        "5. ContextSanitizer - PII protection + Model Armor",
        "6. ToolExposureController - Access control policies"
    ]
    
    ax.text(1, legend_y_start - 0.8, "✅ MANDATORY CONTROLS (6/9):", 
            fontsize=12, fontweight='bold', color=colors['security_arrow'])
    
    for i, control in enumerate(mandatory_controls):
        ax.text(1.2, legend_y_start - 1.3 - (i * 0.4), control,
                fontsize=10, color=colors['text'],
                bbox=dict(boxstyle="round,pad=0.2", facecolor=colors['security'], alpha=0.6))
    
    # Optional controls
    optional_controls = [
        "7. ServerNameRegistry - Server identity verification",
        "8. SemanticMappingValidator - Tool metadata validation"
    ]
    
    ax.text(1, legend_y_start - 4, "🔶 OPTIONAL CONTROLS (2/9):", 
            fontsize=12, fontweight='bold', color='#F57F17')
    
    for i, control in enumerate(optional_controls):
        ax.text(1.2, legend_y_start - 4.5 - (i * 0.4), control,
                fontsize=10, color=colors['text'],
                bbox=dict(boxstyle="round,pad=0.2", facecolor=colors['optional'], alpha=0.6))
    
    # Skipped control
    ax.text(1, legend_y_start - 5.8, "❌ SKIPPED CONTROL (1/9):", 
            fontsize=12, fontweight='bold', color='#D32F2F')
    
    ax.text(1.2, legend_y_start - 6.3, "9. OPAPolicyClient - Use ToolExposureController instead",
            fontsize=10, color=colors['text'],
            bbox=dict(boxstyle="round,pad=0.2", facecolor=colors['skipped'], alpha=0.6))
    
    # Add constraints box
    constraints_y = 2.5
    constraint_box = FancyBboxPatch(
        (7, constraints_y - 1), 4, 2,
        boxstyle="round,pad=0.2",
        facecolor='#FFEBEE',
        edgecolor='#D32F2F',
        linewidth=2
    )
    ax.add_patch(constraint_box)
    
    ax.text(9, constraints_y, "⚠️ OUT-OF-BOX CONSTRAINTS", 
            ha='center', fontsize=12, fontweight='bold', color='#D32F2F')
    ax.text(9, constraints_y - 0.4, "• Agent: No custom security access", 
            ha='center', fontsize=10, color='#D32F2F')
    ax.text(9, constraints_y - 0.7, "• LLM: No custom security access", 
            ha='center', fontsize=10, color='#D32F2F')
    
    # Set title and formatting
    ax.set_title('🚀 GitHub Copilot Agent with MCP Server\nEnd-to-End Security Flow', 
                 fontsize=16, fontweight='bold', pad=20, color=colors['text'])
    
    # Remove axes and set limits
    ax.set_xlim(0, 12)
    ax.set_ylim(0.5, 20)
    ax.axis('off')
    
    # Add timestamp and source
    ax.text(11.5, 0.8, f"Generated: September 4, 2025\nSource: SECURITY_CONTROLS_OVERVIEW.md", 
            ha='right', va='bottom', fontsize=8, style='italic', alpha=0.7)
    
    plt.tight_layout()
    return fig

def main():
    print("🎨 Generating VSCode Copilot Agent MCP Server Sequence Diagram PNG...")
    
    # Create the diagram
    fig = create_sequence_diagram()
    
    # Save as PNG with high quality
    output_file = "VSCode_Copilot_Agent_MCP_Server_Sequence_Diagram.png"
    fig.savefig(output_file, dpi=300, bbox_inches='tight', 
                facecolor='white', edgecolor='none')
    
    print(f"✅ Successfully created: {output_file}")
    print(f"📏 Diagram dimensions: 16x20 inches at 300 DPI")
    print(f"🔒 Security controls: 6 mandatory + 2 optional + 1 skipped")
    
    plt.close()

if __name__ == "__main__":
    main()
