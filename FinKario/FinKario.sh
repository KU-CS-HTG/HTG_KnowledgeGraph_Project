api_base="your_api_base"
api_key="your_api_key"
tushare_token="your_tushare_token"


WORKING_DIR="./src/backtest/backtest_FinKario"
mkdir -p "$WORKING_DIR"



# 1. Construct Attribute graph
# The "date range" should be setted before running the code
python attribute_knowledge_extraction.py \
    --api_base "$api_base" \
    --api_key "$api_key"

# 2. Refine_Attribute graph
python refinement.py 

# 3. Construct Event graph
# The "date range" should be setted before running the code
python event_extraction.py \
    --api_base "$api_base" \
    --api_key "$api_key"

# 4. Merge the two graphs into FinKario
python combine_graphs.py

# # # ------------------------- FinKario -------------------------

# 5. KG embedding & query
#     Note. You can generate the dataset by running the code, or you can download the dataset from the provided link (FinKario datasets/FinKario).
python FinKario-RAG.py \
    --api_base "$api_base" \
    --api_key  "$api_key" \
    --working_dir "$WORKING_DIR"

# # # ------------------------- FinKario-RAG -------------------------

# 6. Backtesting
python backtesting.py \
    --tushare_token "$tushare_token"
    




