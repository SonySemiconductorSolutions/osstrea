""" `setup.py` for OSSTREA """
import os
import setuptools
import setuptools.command.install

class CheckDBExistence(setuptools.command.install.install):
    """
    Custom install command to check for the existence of database/database.json before installation.
    """
    def run(self):
        """Check the existence of the database file."""
        database_path = os.path.join(os.path.dirname(__file__), 'database/database.json')
        if not os.path.exists(database_path):
            raise FileNotFoundError(
                "Error: `database/database.json` not found in the project root. "
                "Please ensure database.json exists before installation."
            )

        super().run()

if __name__ == "__main__":
    setuptools.setup(
        cmdclass={
            'install': CheckDBExistence,
        }
    )
