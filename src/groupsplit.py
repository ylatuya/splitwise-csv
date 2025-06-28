import os
import csv
import sys
import json
import decimal
import pdfplumber
import pickle
import pprint
import urllib
import hashlib
import logging
import optparse
import requests
import webbrowser
import oauthlib.oauth1
from money.money import Money
from money.currency import Currency
from pprint import pprint
from datetime import datetime
from tabulate import tabulate
from abc import ABC, abstractmethod
import appdirs
from typing import List, Dict, Any, Tuple, Optional  # Add typing imports

LOGGING_DISABELED = 100
log_levels = [LOGGING_DISABELED, logging.CRITICAL, logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]
# Adapted from:
# https://docs.python.org/2/howto/logging.html#configuring-logging
# create logger
logger = logging.getLogger(__name__)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)
logging.basicConfig(format="%(asctime)s %(message)s", datefmt="%d/%m/%Y %I:%M:%S %p")


def split(total: Money, num_people: int) -> Tuple[Money, Money]:
    """
    Splits a total to the nearest whole cent and remainder
    Total is a Money() type so no need to worry about floating point errors
    return (2-tuple): base amount owed, remainder of cents which couldn't be evenly split

    Example: >>> split(1.00, 6)
    (0.16, 0.04)
    """
    base = total * 100 // num_people / 100
    extra = total - num_people * base
    assert base * num_people + extra == total, (
        "InternalError:" + " something doesnt add up here: %d * %d + %d != %d" % (base, num_people, extra, total)
    )
    return base, extra


def do_hash(msg: str) -> str:
    m = hashlib.md5()
    m.update(msg.encode("utf-8"))
    return m.hexdigest()


class Splitwise:
    """
    Client for communicating with Splitwise api
    """

    def __init__(self, api_client: str = "oauth_client.pkl") -> None:
        if os.path.isfile(api_client):
            with open(api_client, "rb") as oauth_pkl:
                self.client = pickle.load(oauth_pkl)
        else:
            self.get_client()

    def get_client_auth(self) -> None:
        if os.path.isfile("consumer_oauth.json"):
            with open("consumer_oauth.json", "r") as oauth_file:
                consumer = json.load(oauth_file)
                ckey = consumer["consumer_key"]
                csecret = consumer["consumer_secret"]
        else:
            with open("consumer_oauth.json", "w") as oauth_file:
                json.dump({"consumer_key": "YOUR KEY HERE", "consumer_secret": "YOUR SECRET HERE"}, oauth_file)
            exit(
                "go to https://secure.splitwise.com/oauth_clients to obtain your keys."
                + "place them in consumer_oauth.json"
            )
        self.ckey = ckey
        self.csecret = csecret

    def get_client(self) -> None:
        self.get_client_auth()
        client = oauthlib.oauth1.Client(self.ckey, client_secret=self.csecret)
        uri, headers, body = client.sign("https://secure.splitwise.com/api/v3.0/get_request_token", http_method="POST")
        r = requests.post(uri, headers=headers, data=body)
        resp = r.text.split("&")
        oauth_token = resp[0].split("=")[1]
        oauth_secret = resp[1].split("=")[1]
        uri = "https://secure.splitwise.com/authorize?oauth_token=%s" % oauth_token

        print(uri)
        webbrowser.open_new(uri)

        # proc = subprocess.Popen(['python', 'server.py'], stdout=subprocess.PIPE)
        # stdout, stderr = proc.communicate()
        # if stderr:
        #     exit(stderr)

        verifier_input = input("Copy the oauth verifier from the success page in the browser window : ")

        client = oauthlib.oauth1.Client(
            self.ckey,
            client_secret=self.csecret,
            resource_owner_key=oauth_token,
            resource_owner_secret=oauth_secret,
            verifier=verifier_input,
        )
        # verifier=stdout.strip()) #bYpMPennhuz6bqMRZXd8

        uri, headers, body = client.sign("https://secure.splitwise.com/api/v3.0/get_access_token", http_method="POST")
        resp = requests.post(uri, headers=headers, data=body)
        tokens = resp.text.split("&")
        oauth_token = tokens[0].split("=")[1]
        oauth_secret = tokens[1].split("=")[1]
        client = oauthlib.oauth1.Client(
            self.ckey,
            client_secret=self.csecret,
            resource_owner_key=oauth_token,
            resource_owner_secret=oauth_secret,
            verifier=verifier_input,
        )
        # verifier=stdout.strip())
        with open("oauth_client.pkl", "wb") as pkl:
            pickle.dump(client, pkl)
        self.client = client

    def api_call(self, url: str, http_method: str) -> Dict[str, Any]:
        uri, headers, body = self.client.sign(url, http_method=http_method)
        resp = requests.request(http_method, uri, headers=headers, data=body)
        return resp.json()

    def get_id(self) -> int:
        if not hasattr(self, "my_id"):
            resp = self.api_call("https://secure.splitwise.com/api/v3.0/get_current_user", "GET")
            self.my_id = resp["user"]["id"]
        return self.my_id

    def get_groups(self) -> List[Dict[str, Any]]:
        resp = self.api_call("https://secure.splitwise.com/api/v3.0/get_groups", "GET")
        return resp["groups"]

    def post_expense(self, uri: str) -> None:
        resp = self.api_call(uri, "POST")
        if resp["errors"]:
            sys.stderr.write("URI:")
            sys.stderr.write(uri)
            pprint(resp, stream=sys.stderr)
        else:
            sys.stdout.write(".")
            sys.stdout.flush()

    def delete_expense(self, expense_id: str) -> Dict[str, Any]:
        return self.api_call("https://secure.splitwise.com/api/v3.0/delete_expense/%s" % expense_id, "POST")

    def get_expenses(self, after_date: str = "", limit: int = 0, allow_deleted: bool = True) -> List[Dict[str, Any]]:
        params = {"limit": limit, "updated_after": after_date}
        paramsStr = urllib.urlencode(params)
        resp = self.api_call("https://secure.splitwise.com/api/v3.0/get_expenses?%s" % (paramsStr), "GET")
        if not allow_deleted:
            resp["expenses"] = [exp for exp in resp["expenses"] if exp["deleted_at"] is None]
        return resp["expenses"]


class FileSettings:
    """
    Class to handle settings for file parsing.
    This class is used to configure how the CSV or PDF files are parsed,
    including which columns to use for date, amount, and description,
    whether the first row has titles, and the local currency.
    """

    def __init__(
        self,
        date_col: Optional[int] = None,
        amount_col: Optional[int] = None,
        desc_col: Optional[int] = None,
        local_currency: Currency = Currency.EUR,
        has_title_row: Optional[bool] = None,
    ) -> None:
        self.date_col = date_col
        self.amount_col = amount_col
        self.desc_col = desc_col
        self.has_title_row = has_title_row
        self.local_currency = local_currency


class Settings:
    def __init__(self) -> None:
        self.remember = False
        self.newest_transaction = ""
        self.settings_file = os.path.join(appdirs.user_data_dir("splitwise-csv"), "csv_settings.pkl")

        # Load settings if they exist
        if os.path.isfile(self.settings_file):
            with open(self.settings_file, "rb") as pkl:
                saved_settings = pickle.load(pkl)
                self.__dict__.update(saved_settings.__dict__)
            self.loaded = True

    def configure_rows(self, file_settings: FileSettings, rows: List[List[str]]) -> None:
        """
        Configure row settings based on the provided rows.
        """
        print("These are the first two rows of your csv")
        print("\n".join([str(t) for t in rows[0:2]]))
        print("Column numbers start at 0")
        file_settings.date_col = int(input("Which column has the date?"))
        file_settings.amount_col = int(input("Which column has the amount?"))
        file_settings.desc_col = int(input("Which column has the description?"))
        file_settings.has_title_row = input("Does the first row have titles? [Y/n]").lower() != "n"
        while True:
            try:
                currency_code = input("What currency were these transactions made in? (e.g., USD, EUR): ").upper()
                if currency_code not in Currency.__members__:
                    raise ValueError(f"Invalid currency code: {currency_code}")
                self.local_currency = Currency[currency_code]  # Use Currency from py-money
            except ValueError as e:
                print(e)
                print("Please enter a valid ISO 4217 currency code (e.g., USD, EUR).")
            else:
                break
        self.remember = input("Remember these settings? [Y/n]").lower() != "n"
        breakpoint()
        self.save()

    def save(self) -> None:
        if self.remember:
            os.makedirs(os.path.dirname(self.settings_file), exist_ok=True)
            with open(self.settings_file, "wb") as pkl:
                pickle.dump(self, pkl)

    def __del__(self) -> None:
        self.save()

    def record_newest_transaction(self, rows: List[List[str]]) -> None:
        if self.has_title_row:
            self.newest_transaction = do_hash(str(rows[1]))
        else:
            self.newest_transaction = do_hash(str(rows[0]))


class Expense:
    def __init__(self, date: str, concept: str, amount: Money) -> None:
        self.date = date
        self.concept = concept
        self.amount = amount

    def __repr__(self) -> str:
        return f"Expense(date={self.date}, concept={self.concept}, amount={self.amount})"


class FileParser(ABC):
    @abstractmethod
    def parse(self, settings: Settings, file_path: str) -> List[Expense]:
        """
        Parse the file and return a list of Expense objects.
        """
        pass


class CSVFileParser(FileParser):
    def detect_amount_format(self, rows: List[List[str]], amount_col: int) -> str:
        """
        Detect the decimal separator used in the amount column.
        Returns either '.' or ','.
        """
        dot_count = 0
        comma_count = 0
        for row in rows[:20]:  # Check first 20 rows for a sample
            if len(row) > amount_col:
                value = row[amount_col]
                if "." in value:
                    dot_count += 1
                if "," in value:
                    comma_count += 1
        if comma_count > dot_count:
            return ","
        return "."

    def normalize_amount(self, amount: str, decimal_sep: str) -> str:
        """
        Normalize the amount string to use '.' as decimal separator and remove thousands separators.
        """
        amount = amount.strip().replace(" ", "")
        if decimal_sep == ",":
            # Remove dots (thousands), replace comma with dot (decimal)
            amount = amount.replace(".", "").replace(",", ".")
        else:
            # Remove commas (thousands)
            parts = amount.split(".")
            if len(parts) > 2:
                # e.g. 1.234.567.89
                amount = "".join(parts[:-1]) + "." + parts[-1]
            else:
                amount = amount.replace(",", "")
        return amount

    def detect_date_format(self, rows: List[List[str]], date_col: int) -> str:
        """
        Detect the date format used in the date column.
        Returns either "%m/%d/%Y" or "%d/%m/%Y".
        """
        for row in rows[:20]:  # Check first 20 rows for a sample
            if len(row) > date_col:
                date_str = row[date_col].strip()
                try:
                    parts = date_str.split("/")
                    if len(parts) == 3:
                        first, second, _ = int(parts[0]), int(parts[1]), int(parts[2])
                        # If first number > 12, it must be day (dd/mm/yyyy)
                        if first > 12:
                            return "%d/%m/%Y"
                        # If second number > 12, it must be month (mm/dd/yyyy)
                        elif second > 12:
                            return "%m/%d/%Y"
                except (ValueError, IndexError):
                    continue
        # Default to mm/dd/yyyy if we can't determine
        return "%m/%d/%Y"

    def parse_date(self, date: str):
        """Parse date from CSV row. Can be overridden by subclasses."""
        return datetime.strptime(date, self.date_format).strftime("%Y-%m-%dT%H:%M:%SZ")

    def parse_amount(self, amount: str) -> Money:
        """Parse amount from CSV row. Can be overridden by subclasses."""
        return Money(amount, self.settings.local_currency)

    def parse_concept(self, concept: str) -> str:
        """Parse concept/description from CSV row. Can be overridden by subclasses."""
        return concept.strip()

    def parse(self, settings: Settings, file_path: str) -> List[Expense]:
        expenses = []
        delimiter = self._detect_delimiter(file_path)
        with open(file_path, "r") as csvfile:
            reader = csv.reader(csvfile, delimiter=delimiter)
            rows = list(reader)
            self.settings = self.get_settings(settings, rows)

            # Detect date format once
            self.date_format = self.detect_date_format(rows, self.settings.date_col)

            # Detect amount format once
            decimal_sep = self.detect_amount_format(rows, self.settings.amount_col)

            # Skip header row if it exists
            start_row = 1 if self.settings.has_title_row else 0

            for row in rows[start_row:]:
                try:
                    date = self.parse_date(row[self.settings.date_col])
                    normalized_amount = self.normalize_amount(row[self.settings.amount_col], decimal_sep)
                    amount = self.parse_amount(normalized_amount)
                    concept = self.parse_concept(row[self.settings.desc_col])
                    expenses.append(Expense(date, concept, amount))
                except (ValueError, IndexError):
                    continue
        return expenses

    def get_settings(self, settings, rows):
        if not settings.loaded:
            settings.configure_rows(settings, rows)
        return FileSettings(
            settings.date_col, settings.amount_col, settings.desc_col, settings.local_currency, settings.has_title_row
        )

    def _detect_delimiter(self, file_path: str) -> str:
        """
        Use csv.Sniffer to detect the delimiter in the file.
        """
        with open(file_path, "r") as f:
            sample = f.read(4096)
            f.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=";,")
                return dialect.delimiter
            except csv.Error:
                # Fallback to comma if detection fails
                return ","


class EvoBankCSVFileParser(CSVFileParser):
    def parse_date(self, date_str):
        """
        Parse the date string in Spanish format like '27 JUNIO 2025' into ISO format.
        """
        spanish_months = {
            "ENERO": 1,
            "FEBRERO": 2,
            "MARZO": 3,
            "ABRIL": 4,
            "MAYO": 5,
            "JUNIO": 6,
            "JULIO": 7,
            "AGOSTO": 8,
            "SEPTIEMBRE": 9,
            "OCTUBRE": 10,
            "NOVIEMBRE": 11,
            "DICIEMBRE": 12,
        }
        parts = date_str.strip().split()
        if len(parts) != 3:
            raise ValueError
        day = int(parts[0])
        month = spanish_months[parts[1].upper()]
        year = int(parts[2])
        dt = datetime(year, month, day)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    def parse_amount(self, amount) -> Money:
        """Parse amount from CSV row. Can be overridden by subclasses."""
        amount = amount.split(" ")[0].replace(".", "").replace(",", ".").replace("-", "")
        return Money(amount, self.settings.local_currency)

    def get_settings(self, settings, rows):
        return FileSettings(3, 0, 2, Currency["EUR"], True)


class BankinterPDFParser(FileParser):
    def parse(self, settings: Settings, file_path: str) -> List[Expense]:
        expenses = []
        with pdfplumber.open(file_path) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                lines = text.split("\n")
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 3:
                        date = parts[0]
                        try:
                            datetime.strptime(date, "%d/%m/%Y")
                        except ValueError:
                            continue
                        concept = " ".join(parts[1:-1])[5:]
                        try:
                            amount = Money(
                                parts[-1].replace(",", "."), settings.local_currency
                            )  # Use Currency from settings
                        except decimal.InvalidOperation:
                            print("Failed to parse: " + concept)
                            continue
                        expenses.append(Expense(date, concept, amount))
        return expenses


class SplitGenerator:
    def __init__(self, options: optparse.Values, settings: Settings, args: List[str], api: Splitwise) -> None:
        file_path = args[0]
        group_name = args[1]
        self.api = api
        self.options = options
        self.args = args
        self.settings = settings

        # Choose the parser based on file extension
        if file_path.endswith(".csv"):
            filename = os.path.basename(file_path)
            if filename.startswith("movimientosCuenta"):
                parser = EvoBankCSVFileParser()
            else:
                parser = CSVFileParser()
        elif file_path.endswith(".pdf"):
            parser = BankinterPDFParser()
        else:
            raise ValueError("Unsupported file format")

        self.transactions = parser.parse(settings, file_path)
        self.get_group(group_name)
        self.ask_for_payer()  # Ask which member paid for expenses
        self.splits = []
        self.ask_for_splits()

    def get_group(self, name: str) -> None:
        """
        Wrapper around splitwise api for retreiving groups
        by name. Handles error cases: multiple groups with same name,
        no group found, group has no members.

        name: the name of your Splitwise group (case insensitive)
        """
        num_found = 0
        gid = ""
        groups = self.api.get_groups()
        for group in groups:
            if group["name"].lower() == name.lower():
                gid = group["id"]
                self.all_members = group["members"]  # Store all members including current user
                self.other_members = [m for m in group["members"] if m["id"] != self.api.get_id()]
                num_found += 1

        if num_found > 1:
            exit("More than 1 group found with name:" + name)
        elif num_found < 1:
            exit("No matching group with name:" + name)
        elif len(self.other_members) < 1:
            exit("No other members in group with name:" + name)

        self.gid = gid

    def ask_for_payer(self) -> None:
        """
        Ask the user which member paid for the expenses.
        """
        print("Group members:")
        for i, member in enumerate(self.all_members):
            print(f"{i}: {member['first_name']} {member['last_name']}")

        while True:
            try:
                choice = int(input("Which member paid for these expenses? (enter number): "))
                if 0 <= choice < len(self.all_members):
                    self.payer = self.all_members[choice]
                    print(f"Selected payer: {self.payer['first_name']} {self.payer['last_name']}")
                    break
                else:
                    print("Invalid choice. Please enter a valid number.")
            except ValueError:
                print("Please enter a valid number.")

    def ask_for_splits(self) -> None:
        """
        Ask the user whether they would like to split a given expense and if so
        add it to the list of transactions to upload to Splitwise. Gets final
        confirmation before returning.
        """
        print("Found {0} transactions".format(len(self.transactions)))
        for t in self.transactions:
            print(f"{t.date} {t.concept} ${t.amount}.")
        i = 0
        for t in self.transactions:
            if self.options.yes:
                # Ensure amount is positive before adding
                t.amount = abs(t.amount)
                self.splits.append(t)
                continue
            answer = input("%d: %s at %s $%s. Split? [y=yes/n=no/s=stop] " % (i, t.date, t.concept, t.amount)).lower()
            if answer == "y":
                t.amount = abs(t.amount)
                self.splits.append(t)
            elif answer == "s":
                print("Stopping selection early.")
                break
            # else: skip
            i += 1

        print("-" * 40)
        print("Your Chosen Splits")
        print("-" * 40)

        # Convert Expense objects to dictionaries for tabulate
        splits_data = [{"Date": t.date, "Amount": str(t.amount), "Description": t.concept} for t in self.splits]
        print(tabulate(splits_data, headers="keys"))

        # Kill program if user doesn't want to submit splits
        assert self.options.yes or input("Confirm submission? [y/N]").lower() == "y", "User canceled submission"

    def __getitem__(self, index: int) -> str:
        """
        Implement an iterator for SplitGenerator
        for every split in self.splits, emit the URI needed
        to upload that split to Splitwise
        """
        s = self.splits[index]
        one_cent = Money("0.01", self.settings.local_currency)
        num_people = len(self.all_members)
        base, extra = split(s.amount, num_people)
        params = {
            "payment": "false",
            "cost": str(s.amount.amount),
            "description": s.concept,
            "date": s.date,
            "group_id": self.gid,
            "currency_code": self.settings.local_currency.value,
        }

        # Add all members with their shares
        for i, member in enumerate(self.all_members):
            params[f"users__{i}__user_id"] = member["id"]
            if member["id"] == self.payer["id"]:
                params[f"users__{i}__paid_share"] = str(s.amount.amount)
            else:
                params[f"users__{i}__paid_share"] = "0"

            # Distribute owed shares evenly, with extra cents to first members
            owed_share = base + (one_cent if extra.amount > 0 else Money("0", self.settings.local_currency))
            params[f"users__{i}__owed_share"] = str(owed_share.amount)
            if extra.amount > 0:
                extra -= one_cent

        paramsStr = urllib.parse.urlencode(params)
        return "https://secure.splitwise.com/api/v3.0/create_expense?%s" % (paramsStr)


def main() -> None:
    usage = "groupsplit.py [options] <path to csv file> <splitwise group name>"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option(
        "-v", "--verbosity", default=2, dest="verbosity", help="change the logging level (0 - 6) default: 2"
    )
    parser.add_option(
        "-y",
        "",
        default=False,
        action="store_true",
        dest="yes",
        help="split all transactions in csv without confirmation",
    )
    parser.add_option(
        "-d",
        "--dryrun",
        default=False,
        action="store_true",
        dest="dryrun",
        help="prints requests instead of sending them",
    )
    parser.add_option(
        "-a",
        "--all",
        default=False,
        action="store_true",
        dest="try_all",
        help="consider all transactions in csv file no matter whether they were already seen",
    )
    options, args = parser.parse_args()
    logger.setLevel(log_levels[options.verbosity])

    settings = Settings()
    splitwise = Splitwise()
    split_gen = SplitGenerator(options, settings, args, splitwise)
    print("Uploading splits")
    for uri in split_gen:
        if options.dryrun:
            print(uri)
            continue
        splitwise.post_expense(uri)
    sys.stdout.write("\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
