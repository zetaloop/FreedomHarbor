import json
from pathlib import Path
from urllib.request import Request, urlopen

request = Request(
    "https://versionhistory.googleapis.com/v1/chrome/platforms/android/channels/stable/versions"
    "?order_by=version%20desc&page_size=1",
    headers={"User-Agent": "FreedomHarbor"},
)
with urlopen(request) as response:
    major = json.load(response)["versions"][0]["version"].partition(".")[0]

agent = f"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36\n"
Path(__file__).resolve().parents[1].joinpath("src/user-agent.txt").write_text(agent)
print(agent, end="")
