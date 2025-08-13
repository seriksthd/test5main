from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime
import bcrypt
import jwt
import base64
import json


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Security
security = HTTPBearer()
SECRET_KEY = "your-secret-key-here-make-it-secure"

# Define Models
class StatusCheck(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class StatusCheckCreate(BaseModel):
    client_name: str

# Product Models
class Product(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    price: float
    image: str  # base64 encoded image
    category: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ProductCreate(BaseModel):
    name: str
    price: float
    image: str
    category: str

class ProductUpdate(BaseModel):
    name: Optional[str] = None
    price: Optional[float] = None
    image: Optional[str] = None
    category: Optional[str] = None

# Order Models
class CartItem(BaseModel):
    product_id: str
    product_name: str
    price: float
    quantity: int
    image: str

class Order(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    cart_items: List[CartItem]
    status: str = "pending"  # pending, ready, delivered
    client_name: str
    phone: str
    total_price: float
    created_at: datetime = Field(default_factory=datetime.utcnow)

class OrderCreate(BaseModel):
    cart_items: List[CartItem]
    client_name: str
    phone: str
    total_price: float

class OrderUpdateStatus(BaseModel):
    status: str

# Gallery Models
class GalleryImage(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    image_url: str  # base64 encoded image
    uploaded_at: datetime = Field(default_factory=datetime.utcnow)

class GalleryImageCreate(BaseModel):
    image_url: str

# Admin Models
class AdminLogin(BaseModel):
    username: str
    password: str

class AdminUser(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

# Helper Functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hash: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hash.encode('utf-8'))

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm="HS256")

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Initialize admin user
async def init_admin():
    existing_admin = await db.admin_users.find_one({"username": "admin"})
    if not existing_admin:
        admin_user = AdminUser(
            username="admin",
            password_hash=hash_password("admin123")
        )
        await db.admin_users.insert_one(admin_user.dict())

# Original routes
@api_router.get("/")
async def root():
    return {"message": "Cafe Delicious API"}

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.dict()
    status_obj = StatusCheck(**status_dict)
    await db.status_checks.insert_one(status_obj.dict())
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    status_checks = await db.status_checks.find().to_list(1000)
    return [StatusCheck(**status_check) for status_check in status_checks]

# Admin Authentication Routes
@api_router.post("/admin/login")
async def admin_login(login_data: AdminLogin):
    admin = await db.admin_users.find_one({"username": login_data.username})
    if not admin or not verify_password(login_data.password, admin["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token({"username": admin["username"], "user_id": admin["id"]})
    return {"access_token": token, "token_type": "bearer"}

@api_router.get("/admin/verify")
async def verify_admin(token_data: dict = Depends(verify_token)):
    return {"message": "Token valid", "user": token_data}

# Product Management Routes
@api_router.post("/products", response_model=Product)
async def create_product(product: ProductCreate, token_data: dict = Depends(verify_token)):
    product_obj = Product(**product.dict())
    await db.products.insert_one(product_obj.dict())
    return product_obj

@api_router.get("/products", response_model=List[Product])
async def get_products():
    products = await db.products.find().to_list(1000)
    return [Product(**product) for product in products]

@api_router.get("/products/{product_id}", response_model=Product)
async def get_product(product_id: str):
    product = await db.products.find_one({"id": product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return Product(**product)

@api_router.put("/products/{product_id}", response_model=Product)
async def update_product(product_id: str, product_update: ProductUpdate, token_data: dict = Depends(verify_token)):
    product = await db.products.find_one({"id": product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    update_data = {k: v for k, v in product_update.dict().items() if v is not None}
    if update_data:
        await db.products.update_one({"id": product_id}, {"$set": update_data})
    
    updated_product = await db.products.find_one({"id": product_id})
    return Product(**updated_product)

@api_router.delete("/products/{product_id}")
async def delete_product(product_id: str, token_data: dict = Depends(verify_token)):
    result = await db.products.delete_one({"id": product_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    return {"message": "Product deleted successfully"}

# Order Management Routes
@api_router.post("/orders", response_model=Order)
async def create_order(order: OrderCreate):
    order_obj = Order(**order.dict())
    await db.orders.insert_one(order_obj.dict())
    return order_obj

@api_router.get("/orders", response_model=List[Order])
async def get_orders(token_data: dict = Depends(verify_token)):
    orders = await db.orders.find({"status": {"$ne": "delivered"}}).sort("created_at", -1).to_list(1000)
    return [Order(**order) for order in orders]

@api_router.get("/orders/history", response_model=List[Order])
async def get_order_history(token_data: dict = Depends(verify_token)):
    orders = await db.orders.find({"status": "delivered"}).sort("created_at", -1).to_list(1000)
    return [Order(**order) for order in orders]

@api_router.get("/orders/{order_id}", response_model=Order)
async def get_order(order_id: str):
    order = await db.orders.find_one({"id": order_id})
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return Order(**order)

@api_router.put("/orders/{order_id}/status")
async def update_order_status(order_id: str, status_update: OrderUpdateStatus, token_data: dict = Depends(verify_token)):
    if status_update.status not in ["pending", "ready", "delivered"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    result = await db.orders.update_one(
        {"id": order_id}, 
        {"$set": {"status": status_update.status}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"message": "Order status updated successfully"}

@api_router.delete("/orders/{order_id}")
async def delete_order(order_id: str, token_data: dict = Depends(verify_token)):
    result = await db.orders.delete_one({"id": order_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Order not found")
    return {"message": "Order deleted successfully"}

class BulkDeleteOrders(BaseModel):
    order_ids: List[str]

@api_router.post("/orders/bulk-delete")
async def bulk_delete_orders(bulk_delete: BulkDeleteOrders, token_data: dict = Depends(verify_token)):
    result = await db.orders.delete_many({"id": {"$in": bulk_delete.order_ids}})
    return {"message": f"Deleted {result.deleted_count} orders"}

@api_router.delete("/orders/history/clear")
async def clear_order_history(token_data: dict = Depends(verify_token)):
    result = await db.orders.delete_many({"status": "delivered"})
    return {"message": f"Cleared {result.deleted_count} orders from history"}

# Gallery Routes
@api_router.post("/gallery", response_model=GalleryImage)
async def upload_gallery_image(image: GalleryImageCreate, token_data: dict = Depends(verify_token)):
    gallery_obj = GalleryImage(**image.dict())
    await db.gallery.insert_one(gallery_obj.dict())
    return gallery_obj

@api_router.get("/gallery", response_model=List[GalleryImage])
async def get_gallery_images():
    images = await db.gallery.find().sort("uploaded_at", -1).to_list(1000)
    return [GalleryImage(**image) for image in images]

@api_router.delete("/gallery/{image_id}")
async def delete_gallery_image(image_id: str, token_data: dict = Depends(verify_token)):
    result = await db.gallery.delete_one({"id": image_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Image not found")
    return {"message": "Image deleted successfully"}

# Dashboard/Stats Routes
@api_router.get("/admin/dashboard")
async def get_dashboard_stats(token_data: dict = Depends(verify_token)):
    total_products = await db.products.count_documents({})
    total_orders = await db.orders.count_documents({})
    pending_orders = await db.orders.count_documents({"status": "pending"})
    ready_orders = await db.orders.count_documents({"status": "ready"})
    delivered_orders = await db.orders.count_documents({"status": "delivered"})
    active_orders = await db.orders.count_documents({"status": {"$ne": "delivered"}})
    
    # Calculate total revenue
    orders = await db.orders.find().to_list(1000)
    total_revenue = sum(order.get("total_price", 0) for order in orders)
    
    return {
        "total_products": total_products,
        "total_orders": total_orders,
        "active_orders": active_orders,
        "pending_orders": pending_orders,
        "ready_orders": ready_orders,
        "delivered_orders": delivered_orders,
        "total_revenue": total_revenue
    }

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_event():
    await init_admin()

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
