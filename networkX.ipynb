import pandas as pd
import networkx as nx
from collections import Counter
from networkx.algorithms.community import greedy_modularity_communities

# Sample dataframe (replace this with your actual data load)
# df = pd.read_csv("your_email_data.csv")
# Simulated structure:
# df = pd.DataFrame({"from_domain": [...], "to_domain": [...]})

# 🧼 Extract domain if full emails (safe even if already domains)
df["from_domain"] = df["from_domain"].str.extract(r'@?([\w\.-]+\.\w+)$', expand=False).str.lower().str.strip()
df["to_domain"] = df["to_domain"].str.extract(r'@?([\w\.-]+\.\w+)$', expand=False).str.lower().str.strip()

# 📊 Count top senders (phishing suspects)
send_counts = Counter(df["from_domain"])
print("🔝 Top Sending Domains:")
for domain, count in send_counts.most_common(10):
    print(f"{domain} → {count} sent")

# 📊 Count top recipients (potential victims)
recv_counts = Counter(df["to_domain"])
print("\n🎯 Top Targeted Domains:")
for domain, count in recv_counts.most_common(10):
    print(f"{domain} ← {count} received")

# 🌐 Build directed domain graph
G = nx.DiGraph()
edges = df.groupby(["from_domain", "to_domain"]).size().reset_index(name="weight")
for _, row in edges.iterrows():
    G.add_edge(row["from_domain"], row["to_domain"], weight=row["weight"])

# 🧠 Community detection (undirected for modularity)
communities = list(greedy_modularity_communities(G.to_undirected()))
print(f"\n🧩 Detected {len(communities)} communities")

for i, comm in enumerate(communities):
    print(f"  Community {i}: {len(comm)} domains — Sample: {list(comm)[:5]}")

# 🚨 Suspicious sender pattern (high out-degree, low in-degree)
print("\n⚠️ Suspicious High-Volume Senders (likely phishing domains):")
for node in G.nodes():
    out_deg = G.out_degree(node)
    in_deg = G.in_degree(node)
    if out_deg > 10 and in_deg == 0:
        print(f"{node} → {out_deg} targets, {in_deg} inbound")
