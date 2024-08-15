import plotly.graph_objects as go
from collections import defaultdict, Counter

def visualize_summary(summary):
    user_access_logs = summary['User Access Logs']
    admin_action_logs = summary['Admin Action Logs']
    security_event_logs = summary['Security Event Logs']


    categories = set(log['User'] for log in user_access_logs + admin_action_logs + security_event_logs)
    subcategories = ["User Access", "Admin Actions", "Security Events"]


    compliance_matrix = defaultdict(lambda: defaultdict(int))


    for log in user_access_logs:
        compliance_matrix[log['User']]["User Access"] += 1

    for log in admin_action_logs:
        compliance_matrix[log['User']]["Admin Actions"] += 1

    for log in security_event_logs:
        compliance_matrix[log['User']]["Security Events"] += 1


    heatmap_data = []
    hover_texts = []

    for user in categories:
        row = []
        hover_row = []
        for subcategory in subcategories:
            count = compliance_matrix[user][subcategory]
            row.append(count)
            hover_row.append(f"User: {user}<br>Event Type: {subcategory}<br>Count: {count}")
        heatmap_data.append(row)
        hover_texts.append(hover_row)


    fig = go.Figure(data=go.Heatmap(
        z=heatmap_data,
        x=subcategories,
        y=list(categories),
        hoverongaps=False,
        text=hover_texts,
        hoverinfo="text",
        colorscale='RdYlGn_r' 
    ))


    fig.update_layout(
        title='Compliance Heatmap',
        xaxis_title='Event Types',
        yaxis_title='Users',
        xaxis={'side': 'bottom'},
        yaxis_autorange='reversed',  
    )

    fig.show()
