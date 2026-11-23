# ClimateKG Neo4j 로드 재현

```bash
docker run -d --name climatekg-neo4j -p 8687:7687 -p 8474:7474 \
  -e NEO4J_AUTH=neo4j/climatekg123 neo4j:5.26-community
mkdir -p neo4j/cypher
for f in data/*.cypher.gz; do gunzip -c $f > neo4j/cypher/$(basename $f .gz); done
pip install neo4j==5.27.0 tqdm
NEO4J_URI=neo4j://localhost:8687 NEO4J_USER=neo4j NEO4J_PASSWORD=climatekg123 \
  python upload_neo4j.py --date 20260622
```

결과: 133,990 nodes, 755,310 relationships, 2,000 Paper nodes (약 25분 소요, 에러 0건).
`upload_neo4j.py`는 대상 DB의 모든 데이터를 삭제하므로 빈 DB에만 사용하세요.
