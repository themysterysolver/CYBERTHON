# Use Node.js image
FROM node:18

# Set working directory
WORKDIR /app

# Copy package.json and install dependencies
COPY package.json package-lock.json ./
RUN npm install

# Copy app source code
COPY . /app

# Expose React's development port
EXPOSE 3000

# Command to start React
CMD ["npm", "start"]
