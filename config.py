from dotenv import load_dotenv
import os
 
# Dynamically load the .env file based on environment
env = os.getenv("FLASK_ENV", "development")
env_file = f".env.{env}" if env != "development" else ".env"
load_dotenv(env_file)
 
class Config:
    BASE_URL = os.getenv("BASE_URL")
    DEBUG = os.getenv("DEBUG", "False") == "True"
 
class DevelopmentConfig(Config):
    DEBUG = True
 
class ProductionConfig(Config):
    DEBUG = False
 
class StagingConfig(Config):
    DEBUG = False
 
config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "staging": StagingConfig
}