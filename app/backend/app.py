import os
import secrets
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime
import hashlib
import hmac
import json

from marshmallow import Schema, fields, ValidationError #Add marshmallow for validation

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.hash import Hash
from solana.rpc.api import Client, RPCError
from solana.transaction import Transaction, TransactionInstruction, AccountMeta
from solana.system_program import SYS_PROGRAM_ID
#from spl.token.client import Token #Not using this remove to prevent confusion
from spl.token.constants import TOKEN_PROGRAM_ID
from spl.token.instructions import transfer

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/nft_marketplace')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Solana Configuration - ENSURE THESE ARE PROPERLY SET IN YOUR .flaskenv FILE!
SOLANA_NETWORK = os.environ.get("SOLANA_NETWORK", "https://api.devnet.solana.com")
SOLANA_CLIENT = Client(SOLANA_NETWORK)
CRAFT_MINT_ADDRESS = Pubkey.from_string(os.environ.get("CRAFT_MINT_ADDRESS", "Gh9ZwEmdLJ8DscKzPWV7yRyP4c Khalifa mint address")) # Replace with your CRAFT token mint address on devnet OR BETTER, CREATE and MIRDROP TO.