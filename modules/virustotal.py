
import vt
import hashlib

API_KEY = "52c75f95f6de8b4e9b39a48af4330722e8f2eac5e87a28005bf46ff0a1baec76"


def check_file(file):

    file.seek(0)

    file_bytes = file.read()

    if not file_bytes:
        return None, None

    sha256 = hashlib.sha256(file_bytes).hexdigest()

    with vt.Client(API_KEY) as client:

        try:

            vt_file = client.get_object(f"/files/{sha256}")

            stats = vt_file.last_analysis_stats
            print(stats)
            
            return stats, sha256

        except vt.error.APIError:

            return None, sha256