using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace AspNetCore.Identity.MongoDB
{
    public class MongoIdentityBuilder
    {
        public MongoIdentityBuilder(Type user, IServiceCollection services)
        {
            UserType = user;
            Services = services;
        }

        public Type UserType { get; private set; }
        public IServiceCollection Services { get; private set; }

        private MongoIdentityBuilder AddScoped(Type serviceType, Type concreteType)
        {
            Services.AddScoped(serviceType, concreteType);
            return this;
        }

        public virtual MongoIdentityBuilder AddUserValidator<T>() where T : class
        {
            return AddScoped(typeof(IUserValidator<>).MakeGenericType(UserType), typeof(T));
        }

        public virtual MongoIdentityBuilder AddClaimsPrincipalFactory<T>() where T : class
        {
            return AddScoped(typeof(IUserClaimsPrincipalFactory<>).MakeGenericType(UserType), typeof(T));
        }

        public virtual MongoIdentityBuilder AddErrorDescriber<TDescriber>() where TDescriber : IdentityErrorDescriber
        {
            Services.AddScoped<IdentityErrorDescriber, TDescriber>();
            return this;
        }

        public virtual MongoIdentityBuilder AddPasswordValidator<T>() where T : class
        {
            return AddScoped(typeof(IPasswordValidator<>).MakeGenericType(UserType), typeof(T));
        }

        public virtual MongoIdentityBuilder AddUserStore<T>() where T : class
        {
            return AddScoped(typeof(IUserStore<>).MakeGenericType(UserType), typeof(T));
        }

        public virtual MongoIdentityBuilder AddTokenProvider<TProvider>(string providerName) where TProvider : class
        {
            return AddTokenProvider(providerName, typeof(TProvider));
        }

        public virtual MongoIdentityBuilder AddTokenProvider(string providerName, Type provider)
        {
            Services.Configure<IdentityOptions>(options =>
            {
                options.Tokens.ProviderMap[providerName] = new TokenProviderDescriptor(provider);
            });

            Services.AddSingleton(provider);
            return this;
        }

        public virtual MongoIdentityBuilder AddDefaultTokenProvider()
        {
            var dataProtectionProviderType = typeof(DataProtectorTokenProvider<>).MakeGenericType(typeof(MongoIdentityUser));
            var phoneNumberProviderType = typeof(PhoneNumberTokenProvider<>).MakeGenericType(typeof(MongoIdentityUser));
            var emailTokenProviderType = typeof(EmailTokenProvider<>).MakeGenericType(typeof(MongoIdentityUser));
            return AddTokenProvider(TokenOptions.DefaultProvider, dataProtectionProviderType)
                .AddTokenProvider(TokenOptions.DefaultEmailProvider, emailTokenProviderType)
                .AddTokenProvider(TokenOptions.DefaultPhoneProvider, phoneNumberProviderType);
        }

    }
}
