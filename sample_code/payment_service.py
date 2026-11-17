"""Intentionally vulnerable demo service used to showcase CodeGuard AI. Never deploy this file."""
import hashlib
import json
import os
import pickle
import sqlite3
import subprocess

import requests

DEBUG = True
password = "admin123"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgres://admin:SuperSecret99@db.internal:5432/payments"


def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()


def find_orders(customer):
    conn = sqlite3.connect("app.db")
    return conn.execute(f"SELECT * FROM orders WHERE customer = '{customer}'").fetchall()


def process_payment():
    pass


def refund_payment(order_id):
    raise NotImplementedError


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def run_report(name):
    os.system("generate_report.sh " + name)
    subprocess.call("zip reports.zip " + name, shell=True)


def load_session(blob):
    return pickle.loads(blob)


def charge_card(card, amount, items=[]):
    # TODO: validate card number and amount
    # In a real application you would call the payment gateway here
    items.append(amount)
    try:
        resp = requests.post("https://api.payments.example/charge", json={"card": card, "amount": amount}, verify=False)
        return resp.json()
    except:
        pass


def calculate_discount(order):
    total = 0
    for item in order["items"]:
        total += item["price"] * item["qty"]
    if total > 100:
        total = total * 0.9
    return round(total, 2)


def calculate_invoice_total(order):
    total = 0
    for item in order["items"]:
        total += item["price"] * item["qty"]
    if total > 100:
        total = total * 0.9
    return round(total, 2)


def parse_config(raw):
    return eval(raw)


def notify(user):
    print("Sending reset token for", user, "password:", password)
    # ... rest of the code remains the same
