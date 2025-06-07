from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db, User
from sqlalchemy.exc import SQLAlchemyError

medical_bp = Blueprint('medical', __name__)

@medical_bp.route('/api/medical/professionals', methods=['GET'])
@jwt_required()
def get_available_professionals():
    """Get a list of available medical professionals"""
    try:
        professionals = User.query.filter_by(is_medical_professional=True).all()
        return jsonify({
            'success': True,
            'professionals': [
                {
                    'id': prof.id,
                    'name': prof.name or 'Dr. ' + prof.email.split('@')[0].title(),
                    'available': True  # In a real app, this would be determined dynamically
                } for prof in professionals
            ]
        })
    except SQLAlchemyError as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@medical_bp.route('/api/medical/request', methods=['POST'])
@jwt_required()
def request_medical_chat():
    """Request a chat with a medical professional"""
    try:
        user_id = get_jwt_identity()
        professional_id = request.json.get('professional_id')
        
        if not professional_id:
            return jsonify({'success': False, 'error': 'Professional ID is required'}), 400
            
        # In a real app, this would create a chat request in the database
        # and notify the medical professional
        
        return jsonify({
            'success': True,
            'message': 'Chat request sent successfully',
            'estimated_wait_time': '5 minutes'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500